#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qemu/log.h"

#define TYPE_VIRT_PASSTHROUGH_TEE          "virt-passthrough-tee"
#define VIRT_PASSTHROUGH_TEE(obj)          OBJECT_CHECK(VirtPassthroughTeeState, (obj), TYPE_VIRT_PASSTHROUGH_TEE)

/* Register map */
#define REG_ID                 0x0
#define CHIP_ID                0xf001

#define REG_INIT               0x4
#define CHIP_EN                BIT(0)

#define REG_CMD                0x8

#define REG_INT_STATUS         0xc
#define INT_ENABLED            BIT(0)
#define INT_BUFFER_DEQ         BIT(1)

typedef struct {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    // qemu_irq irq;
    uint32_t id;
    uint32_t init;
    uint32_t cmd;
    uint32_t status;
} VirtPassthroughTeeState;

// static void virt_passthrough_tee_set_irq(VirtPassthroughTeeState *s, int irq)
// {
//     s->status = irq;
//     qemu_set_irq(s->irq, 1);
// }
// 
// static void virt_passthrough_tee_clr_irq(VirtPassthroughTeeState *s)
// {
//     qemu_set_irq(s->irq, 0);
// }

static uint64_t virt_passthrough_tee_read(void *opaque, hwaddr offset, unsigned size)
{
    VirtPassthroughTeeState *s = (VirtPassthroughTeeState *)opaque;
    bool is_enabled = s->init & CHIP_EN;

    if (!is_enabled) {
        fprintf(stderr, "Device is disabled\n");
        return 0;
    }


    printf("READ FROM TEE PASSTHROUGH AT OFF=%lx  SIZE=%u\n", offset, size);

    return 0;
}

static void virt_passthrough_tee_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    // VirtPassthroughTeeState *s = (VirtPassthroughTeeState *)opaque;
    printf("WRITE TO TEE PASSTHROUGH AT OFF=%ld  SIZE=%u   VAL=%lx\n", offset, size, value);
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


    // sysbus_init_irq(sbd, &s->irq);

    s->id = CHIP_ID; 
    s->init = 0;
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
