#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include <linux/tee.h>
#include <sys/ioctl.h>

#define TYPE_VIRT_PASSTHROUGH_TEE          "virt-passthrough-tee"
#define VIRT_PASSTHROUGH_TEE(obj)          OBJECT_CHECK(VirtPassthroughTeeState, (obj), TYPE_VIRT_PASSTHROUGH_TEE)

/* Register map */
#define REG_OPEN_TEE            0x0
#define REG_CLOSE_TEE           0x8

#define REG_STATUS              0x10
#define REG_STATUS_FLAG_BUSY    BIT(0)
#define REG_STATUS_FLAG_ERROR   BIT(1)

#define REG_IOCTL_NUM                   0x18
#define REG_IOCTL_PHYS_DATA_BUFFER      0x20
#define REG_IOCTL_PHYS_DATA_BUFFER_LEN  0x28
// Warning: The FD register is 4 bytes because we want to guarantee
// that a single write will trigger the operation
#define REG_IOCTL_FD                    0x30

#define REG_TEST    0x50

#define DEFAULT_TEE_PATH "/dev/tee0"

struct TeeConnectionState {
    int fd;
};

typedef struct {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    
    uint32_t status;
    uint64_t ioctl_phys_data_buffer_ptr, ioctl_phys_data_buffer_len;
    uint64_t ioctl_num;
    uint64_t return_value;
    
    struct {
        unsigned capacity, length;
        struct TeeConnectionState *data;
    } tee_connections;
} VirtPassthroughTeeState;

static int convert_guest_fd_to_host_fd(VirtPassthroughTeeState *s, int guest_fd, int *out_fd)
{
    if (guest_fd < 0 || guest_fd >= s->tee_connections.length)
        return -1;
    
    // FIXME: It's a bad idea to assume the guest_fd is the index inside this array
    *out_fd = s->tee_connections.data[guest_fd].fd;
    return 0;
}

static uint32_t open_new_tee_connection(VirtPassthroughTeeState *s)
{
    int fd = open(DEFAULT_TEE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("[qemu]: failed to open " DEFAULT_TEE_PATH);
        s->status |= REG_STATUS_FLAG_ERROR;
        return 0;
    }

    if (s->tee_connections.length == s->tee_connections.capacity) {
        s->tee_connections.capacity += 8;
        s->tee_connections.data = g_renew(struct TeeConnectionState, s->tee_connections.data, s->tee_connections.capacity);
    }
    s->tee_connections.data[s->tee_connections.length++] = (struct TeeConnectionState){.fd = fd};
    printf("Opened a new tee connection: %d at index %d\n", fd, s->tee_connections.length - 1);

    return s->tee_connections.length - 1;
}

static void close_tee_connection(VirtPassthroughTeeState *s, uint64_t fd)
{
    if (fd >= s->tee_connections.length) {
        s->status |= REG_STATUS_FLAG_ERROR;
        return;
    }

    // FIXME: We need to remove the connection from s->tee_connections
    //        We can't simply remove it and move all back one element
    //        because the client expects the descriptors to be constant
    close((int) fd);
}

static uint64_t handle_tee_ioc_version(
    int fd, 
    uint64_t phys_data_buffer_ptr, uint64_t phys_data_buffer_len, 
    uint32_t *status
)
{
    struct tee_ioctl_version_data *temp_buffer;
    if (sizeof(*temp_buffer) > phys_data_buffer_len) {
        // FIXME: Handle this case
        *status |= REG_STATUS_FLAG_ERROR;
        assert(false);
        return -ENOMEM;
    }

    temp_buffer = g_malloc0(phys_data_buffer_len);
    if (ioctl(fd, TEE_IOC_VERSION, temp_buffer)) {
        *status = REG_STATUS_FLAG_ERROR;
        g_free(temp_buffer);
        perror("[qemu]: ioctl fail");
        assert(false);
        return errno;
    }
    printf("[qemu]: ver=%x\n", temp_buffer->impl_id);

    cpu_physical_memory_write(phys_data_buffer_ptr, temp_buffer, phys_data_buffer_len);
    g_free(temp_buffer);
    
    return 0;
}

static uint64_t handle_tee_ioc_open_session(
    int fd, 
    uint64_t phys_data_buffer_ptr, uint64_t phys_data_buffer_len, 
    uint32_t *status
)
{
    return 0;
}

static uint64_t handle_ioctl_request(
    int real_fd, 
    uint64_t ioctl_num, 
    uint64_t phys_data_buffer_ptr, uint64_t phys_data_buffer_len,
    uint32_t *status
)
{
    printf(
        "handle_ioctl_request(fd=%d, ioctl=%lx, buffer={.ptr=%lx, .len=%ld)\n",
        real_fd, ioctl_num, phys_data_buffer_ptr, phys_data_buffer_len
    );

    switch(ioctl_num) {
    case TEE_IOC_VERSION:
        return handle_tee_ioc_version(real_fd, phys_data_buffer_ptr, phys_data_buffer_len, status);
    case TEE_IOC_OPEN_SESSION:
        return handle_tee_ioc_open_session(real_fd, phys_data_buffer_ptr, phys_data_buffer_len, status);
    default:
        *status |= REG_STATUS_FLAG_ERROR;
        assert(false);
        return -ENOTSUP;
    }
}

static uint64_t virt_passthrough_tee_read(void *opaque, hwaddr offset, unsigned size)
{
    uint64_t result;
    VirtPassthroughTeeState *s = (VirtPassthroughTeeState *)opaque;

    // printf("READ FROM TEE PASSTHROUGH AT OFF=%lx  SIZE=%u\n", offset, size);

    if (offset == REG_OPEN_TEE) {
        s->status = REG_STATUS_FLAG_BUSY;
        result = open_new_tee_connection(s);
    } else if (offset == REG_STATUS) {
        result = s->status;
    } else {
        assert(false);
    }

    s->status &= ~REG_STATUS_FLAG_BUSY;
    return result;
}

static void virt_passthrough_tee_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    /*
        Even though we have a 'size' param and 'value' is a uint64_t,
        8 byte writes are actually split into two 4 bytes writes, with
        the offset shifted by 4 bytes at the second write but the
        bytes to write are always in the lower ones of 'value'

        These macros simplify the bit-hacking stuff for combining
        the writes.
     */
#define SET_OFFSET_4_BYTES(old, expected, actual, new_value) \
    ((old) & (0x00000000ffffffff << (8 * ((actual) - (expected))))) | ((new_value) << (8 * ((actual) - (expected))))

#define IS_VALID_REGISTER_WRITE(size, register, offset) \
    (size) == 4 && ((offset) == (register) || (offset) == (register) + 4)
    char local_buf[4];
    

    VirtPassthroughTeeState *s = (VirtPassthroughTeeState *)opaque;
    
    if (offset == REG_TEST) {

        cpu_physical_memory_read(value, local_buf, 4);
        printf("[qemu]: read (%d %d %d %d) from %lx\n",
            (int) local_buf[0],
            (int) local_buf[1],
            (int) local_buf[2],
            (int) local_buf[3],
            value
        );

        printf("[qemu]: test printing to %lx\n", value);
        const char buf[] = {0xa, 0xb, 0xc, 0xd};
        cpu_physical_memory_write(value, buf, 4);
        return;
    }
    
    s->status = REG_STATUS_FLAG_BUSY;

    printf("WRITE TO TEE PASSTHROUGH AT OFF=%ld  SIZE=%u   VAL=%lx\n", offset, size, value);

    if (offset == REG_CLOSE_TEE) {
        close_tee_connection(s, value);
    } else if (IS_VALID_REGISTER_WRITE(size, REG_IOCTL_PHYS_DATA_BUFFER, offset)) {
        s->ioctl_phys_data_buffer_ptr = SET_OFFSET_4_BYTES(s->ioctl_phys_data_buffer_ptr, REG_IOCTL_PHYS_DATA_BUFFER, offset, value);
    } else if (IS_VALID_REGISTER_WRITE(size, REG_IOCTL_PHYS_DATA_BUFFER_LEN, offset)) {
        s->ioctl_phys_data_buffer_len = SET_OFFSET_4_BYTES(s->ioctl_phys_data_buffer_len, REG_IOCTL_PHYS_DATA_BUFFER_LEN, offset, value);
    } else if (IS_VALID_REGISTER_WRITE(size, REG_IOCTL_NUM, offset)) {
        s->ioctl_num = SET_OFFSET_4_BYTES(s->ioctl_num, REG_IOCTL_NUM, offset, value);
    } else if (offset == REG_IOCTL_FD && size == 4) {

        int fd = (int) value;
        bool need_to_close_fd = false;
        if (s->ioctl_num == TEE_IOC_VERSION && fd == 0) {
            fd = open(DEFAULT_TEE_PATH, O_RDONLY);
            need_to_close_fd = true;
        } else if (convert_guest_fd_to_host_fd(s, fd, &fd)) {
            assert(false);
            // Invalid fd
            s->status |= REG_STATUS_FLAG_ERROR;
            goto end;
        }

        s->return_value = handle_ioctl_request(
            fd,
            s->ioctl_num,
            s->ioctl_phys_data_buffer_ptr,
            s->ioctl_phys_data_buffer_len,
            &s->status
        );

        if (need_to_close_fd)
            close(fd);
    }

end:
    s->status &= ~REG_STATUS_FLAG_BUSY;
}

static const MemoryRegionOps virt_tee_passthrough_ops = {
    .read = virt_passthrough_tee_read,
    .write = virt_passthrough_tee_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void virt_passthrough_tee_realize(DeviceState *d, Error **errp)
{
    VirtPassthroughTeeState *s = VIRT_PASSTHROUGH_TEE(d);
    SysBusDevice *sbd = SYS_BUS_DEVICE(d);

    memory_region_init_io(&s->iomem, OBJECT(s), &virt_tee_passthrough_ops, s,
                          TYPE_VIRT_PASSTHROUGH_TEE, 0x200);
    sysbus_init_mmio(sbd, &s->iomem);

    s->status = 0;

#define INITIAL_CAPACITY 4

    s->tee_connections.capacity = INITIAL_CAPACITY;
    s->tee_connections.length = 0;
    s->tee_connections.data = g_new(struct TeeConnectionState, INITIAL_CAPACITY); 
}

static void virt_passthrough_tee_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = virt_passthrough_tee_realize;
}

static const TypeInfo virt_passthrough_tee_info = {
    .name          = TYPE_VIRT_PASSTHROUGH_TEE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VirtPassthroughTeeState),
    .class_init    = virt_passthrough_tee_class_init,
};

static void virt_passthrough_tee_register_types(void)
{
    type_register_static(&virt_passthrough_tee_info);
}

type_init(virt_passthrough_tee_register_types)
