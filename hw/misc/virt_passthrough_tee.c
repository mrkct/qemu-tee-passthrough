// This include needs to be the first
// clang-format off
#include "qemu/osdep.h"
// clang-format on
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include <linux/tee.h>
#include <sys/ioctl.h>
#include "register_map.h"

#define TYPE_VIRT_PASSTHROUGH_TEE "virt-passthrough-tee"
#define VIRT_PASSTHROUGH_TEE(obj)                                              \
	OBJECT_CHECK(VirtPassthroughTeeState, (obj), TYPE_VIRT_PASSTHROUGH_TEE)

#define DEFAULT_TEE_PATH "/dev/tee0"

// FIXME: This was copy pasted from the TEE client api
#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4


struct HostSharedMemoryBuffer {
	int host_fd;
	uint8_t *mmap_address;

	int64_t host_id;
	int64_t guest_id;
	uint64_t size;
	uint32_t flags;
	uint64_t guest_paddr;
};

struct TeeConnectionState {
	int fd;
	GHashTable *guest_shm_id_to_local_buffer;
};

typedef struct {
	SysBusDevice parent_obj;
	MemoryRegion iomem;

	uint64_t status;
	uint64_t return_value;
	uint64_t command_ptr;

	struct {
		unsigned capacity, length;
		struct TeeConnectionState *data;

	} tee_connections;
} VirtPassthroughTeeState;

static struct TeeConnectionState *
get_associated_tee_connection(VirtPassthroughTeeState *s, int guest_fd)
{
	if (guest_fd < 0 || guest_fd >= s->tee_connections.length) {
		return NULL;
	}

	// FIXME: It's a bad idea to assume the guest_fd is the index inside this
	// array
	return &s->tee_connections.data[guest_fd];
}

static int convert_guest_fd_to_host_fd(VirtPassthroughTeeState *s, int guest_fd,
				       int *out_fd)
{
	struct TeeConnectionState *conn =
		get_associated_tee_connection(s, guest_fd);

	if (conn == NULL)
		return 1;

	*out_fd = conn->fd;
	return 0;
}

static uint32_t open_new_tee_connection(VirtPassthroughTeeState *s)
{
	int fd = open(DEFAULT_TEE_PATH, O_RDONLY);
	if (fd < 0) {
		perror("[qemu]: failed to open " DEFAULT_TEE_PATH);
		s->status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return 0;
	}

	// FIXME: Use a GHashTable instead. See the FIXME in close_tee_connection
	if (s->tee_connections.length == s->tee_connections.capacity) {
		s->tee_connections.capacity += 8;
		s->tee_connections.data = g_renew(struct TeeConnectionState,
						  s->tee_connections.data,
						  s->tee_connections.capacity);
	}

	s->tee_connections.data[s->tee_connections.length++] =
		(struct TeeConnectionState){
			.fd = fd,
			.guest_shm_id_to_local_buffer = g_hash_table_new_full(
				g_int64_hash, g_int64_equal, g_free, g_free)
		};

	return s->tee_connections.length - 1;
}

static void close_tee_connection(VirtPassthroughTeeState *s, uint64_t guest_fd)
{
	struct TeeConnectionState *connection;
	connection = get_associated_tee_connection(s, guest_fd);

	if (connection == NULL) {
		s->status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return;
	}

	// FIXME: We need to remove the connection from s->tee_connections
	//        We can't simply remove it and move all back one element
	//        because the client expects the descriptors to be constant

	close((int)connection->fd);
	g_hash_table_destroy(connection->guest_shm_id_to_local_buffer);
}

static void sync_shared_memory_buffers_in_params_guest_to_host(
	struct TeeConnectionState *conn, struct tee_ioctl_param params[],
	size_t num_params)
{
	struct HostSharedMemoryBuffer *buf;
	uint64_t offset, buffer_size;
	int i;
	int64_t guest_shmem_id, key;

	for (i = 0; i < num_params; i++) {
		if (params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT &&
		    params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT)
			continue;

		offset = params[i].a;
		buffer_size = params[i].b;
		guest_shmem_id = (int64_t)params[i].c;

		// FIXME: Technically they can pass a NULL ptr,
		// see (section 3.2.5 memory references) http://www.globalplatform.org/specificationsdevice.asp
		key = guest_shmem_id;
		buf = g_hash_table_lookup(conn->guest_shm_id_to_local_buffer,
					  &key);
		assert(buf != NULL);

		assert(offset < buf->size);
		assert(buffer_size <= buf->size);
		assert(offset + buffer_size <= buf->size);
		cpu_physical_memory_read(buf->guest_paddr + offset,
					 &buf->mmap_address[offset],
					 buffer_size);
	}
}

static void sync_shared_memory_buffers_in_params_host_to_guest(
	struct TeeConnectionState *conn, struct tee_ioctl_param params[],
	size_t num_params)
{
	struct HostSharedMemoryBuffer *buf;
	uint64_t offset, buffer_size;
	int i;
	int64_t guest_shmem_id, key;

	for (i = 0; i < num_params; i++) {
		if (params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT &&
		    params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT)
			continue;

		offset = params[i].a;
		buffer_size = params[i].b;
		guest_shmem_id = (int64_t)params[i].c;

		// FIXME: Technically they can pass a NULL ptr,
		// see (section 3.2.5 memory references) http://www.globalplatform.org/specificationsdevice.asp
		key = guest_shmem_id;
		buf = g_hash_table_lookup(conn->guest_shm_id_to_local_buffer,
					  &key);
		assert(buf != NULL);

		assert(offset < buf->size);
		assert(buffer_size <= buf->size);
		assert(offset + buffer_size <= buf->size);
		cpu_physical_memory_write(buf->guest_paddr + offset,
					  &buf->mmap_address[offset],
					  buffer_size);
	}
}

static void
temporarily_substitute_guest_memrefs_in_params_with_associated_host_memrefs(
	struct TeeConnectionState *conn, int64_t **host2guest_shmem_id_map,
	struct tee_ioctl_param params[], size_t num_params)
{
	struct HostSharedMemoryBuffer *buf;
	int64_t guest_shmem_id, key;
	int i;

	assert(*host2guest_shmem_id_map == NULL);
	// this gets free'd in 'convert_back_host_memrefs_with_associated_guest_memrefs'
	*host2guest_shmem_id_map =
		g_new(int64_t, TEEC_CONFIG_PAYLOAD_REF_COUNT);

	for (i = 0; i < num_params; i++) {
		(*host2guest_shmem_id_map)[i] = -1;
		if (params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT &&
		    params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT &&
		    params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT)
			continue;

		guest_shmem_id = (int64_t)params[i].c;

		// FIXME: Technically they can pass a NULL ptr,
		// see (section 3.2.5 memory references) http://www.globalplatform.org/specificationsdevice.asp
		key = guest_shmem_id;
		buf = g_hash_table_lookup(conn->guest_shm_id_to_local_buffer,
					  &key);
		assert(buf != NULL);

		params[i].c = (uint64_t)buf->host_id;
		(*host2guest_shmem_id_map)[i] = (int64_t)guest_shmem_id;
	}
}

static void convert_back_host_memrefs_with_associated_guest_memrefs(
	int64_t **host2guest_shmem_id_map, struct tee_ioctl_param params[],
	size_t num_params)
{
	int i;

	assert(*host2guest_shmem_id_map != NULL);

	for (i = 0; i < num_params; i++) {
		if (params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT &&
		    params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT &&
		    params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT)
			continue;

		params[i].c = (uint64_t)(*host2guest_shmem_id_map)[i];
	}
	g_free(*host2guest_shmem_id_map);
	*host2guest_shmem_id_map = NULL;
}

static uint64_t handle_command_get_version(
	VirtPassthroughTeeState *s,
	uint64_t command_phys_address,
					   uint64_t data_length,
					   uint64_t *status)
{
	int rc;
	struct CommandGetVersion command;

	assert(data_length == sizeof(command));

	int fd = open(DEFAULT_TEE_PATH, O_RDONLY);
	if (fd <= 0) {
		*status = TP_MMIO_REG_STATUS_FLAG_ERROR;
		perror("failed to open " DEFAULT_TEE_PATH);
		assert(false);
		return (uint64_t)fd;
	}

	if ((rc = ioctl(fd, TEE_IOC_VERSION, &command.version_data))) {
		*status = TP_MMIO_REG_STATUS_FLAG_ERROR;
		perror("failed to query tee version for " DEFAULT_TEE_PATH);
		assert(false);
		return rc;
	}

	close(fd);
	// We don't support the following capabilities so let's not advertise them
	// FIXME: Actually support this stuff
	command.version_data.gen_caps &= ~(TEE_GEN_CAP_REG_MEM);
#define TEE_GEN_CAP_MEMREF_NULL (1 << 3) // FIXME: Why is this not defined in the kernel headers? Also, I don't really understand what this is
	command.version_data.gen_caps &= ~(TEE_GEN_CAP_MEMREF_NULL);
#undef TEE_GEN_CAP_MEMREF_NULL

	cpu_physical_memory_write(command_phys_address, &command,
				  sizeof(command));

	return 0;
}

static uint64_t handle_command_open_session(VirtPassthroughTeeState *s,
					    uint64_t command_phys_address,
					    uint64_t data_length,
					    uint64_t *status)
{
	int rc = 0;
	int64_t *host2guest_shm_id_map = NULL;

	struct TeeConnectionState *conn;
	struct tee_ioctl_buf_data buf_data;
	struct CommandOpenSession *command;

	// Verify that the data_length is a sensible value
	const size_t min_byte_size_for_command_and_params =
		sizeof(struct CommandOpenSession);
	const size_t max_byte_size_for_command_and_params =
		sizeof(struct CommandOpenSession) +
		TEEC_CONFIG_PAYLOAD_REF_COUNT * sizeof(struct tee_ioctl_param);

	assert(min_byte_size_for_command_and_params <= data_length);
	assert(data_length <= max_byte_size_for_command_and_params);
	// FIXME: also check that the size is a multiple of sizeof(param) after
	// subtracting sizeof(arg)
	if (data_length < min_byte_size_for_command_and_params ||
	    data_length > max_byte_size_for_command_and_params) {
		rc = -EINVAL;
		goto cleanup;
	}

	// Read the data into a host buffer and prepare for the ioctl
	command = g_malloc0(data_length);
	cpu_physical_memory_read(command_phys_address, command, data_length);
	if ((conn = get_associated_tee_connection(s, command->fd)) == NULL) {
		rc = -EINVAL; // FIXME: probably wrong error code
		goto cleanup;
	}
	buf_data.buf_ptr = (uintptr_t)&command->open_session_arg;
	buf_data.buf_len = sizeof(command->open_session_arg) +
			   sizeof(struct tee_ioctl_param) *
				   command->open_session_arg.num_params;

	sync_shared_memory_buffers_in_params_guest_to_host(
		conn, command->open_session_arg.params,
		command->open_session_arg.num_params);
	temporarily_substitute_guest_memrefs_in_params_with_associated_host_memrefs(
		conn, &host2guest_shm_id_map, command->open_session_arg.params,
		command->open_session_arg.num_params);
	if (ioctl(conn->fd, TEE_IOC_OPEN_SESSION, &buf_data)) {
		rc = errno;
		perror("ioctl open session failed");
		goto cleanup;
	}
	convert_back_host_memrefs_with_associated_guest_memrefs(
		&host2guest_shm_id_map, command->open_session_arg.params,
		command->open_session_arg.num_params);
	sync_shared_memory_buffers_in_params_host_to_guest(
		conn, command->open_session_arg.params,
		command->open_session_arg.num_params);

	cpu_physical_memory_write(command_phys_address, command, data_length);

cleanup:
	if (command != NULL)
		g_free(command);
	if (rc) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
	}

	return rc;
}

static uint64_t handle_command_invoke_function(VirtPassthroughTeeState *s,
					       uint64_t command_phys_address,
					       uint64_t data_length,
					       uint64_t *status)
{
	int rc = 0;

	struct TeeConnectionState *conn = NULL;
	struct tee_ioctl_buf_data buf_data;
	int64_t *host2guest_shm_id_map = NULL;
	struct CommandInvokeFunction *command;

	// Verify that the data_length is a sensible value
	const size_t min_byte_size_for_command_and_params =
		sizeof(struct CommandInvokeFunction);
	const size_t max_byte_size_for_command_and_params =
		sizeof(struct CommandInvokeFunction) +
		TEEC_CONFIG_PAYLOAD_REF_COUNT * sizeof(struct tee_ioctl_param);

	assert(min_byte_size_for_command_and_params <= data_length);
	assert(data_length <= max_byte_size_for_command_and_params);
	// FIXME: also check that the size is a multiple of sizeof(param) after
	// subtracting sizeof(arg)
	if (data_length < min_byte_size_for_command_and_params ||
	    data_length > max_byte_size_for_command_and_params) {
		rc = -EINVAL;
		goto cleanup;
	}

	// Read the data into a host buffer and prepare for the ioctl
	command = g_malloc0(data_length);
	cpu_physical_memory_read(command_phys_address, command, data_length);
	if ((conn = get_associated_tee_connection(s, command->fd)) == NULL) {
		rc = -EINVAL; // FIXME: probably wrong error code
		goto cleanup;
	}
	buf_data.buf_ptr = (uintptr_t)&command->invoke_function_arg;
	buf_data.buf_len = sizeof(command->invoke_function_arg) +
			   sizeof(struct tee_ioctl_param) *
				   command->invoke_function_arg.num_params;

	sync_shared_memory_buffers_in_params_guest_to_host(
		conn, command->invoke_function_arg.params,
		command->invoke_function_arg.num_params);
	temporarily_substitute_guest_memrefs_in_params_with_associated_host_memrefs(
		conn, &host2guest_shm_id_map,
		command->invoke_function_arg.params,
		command->invoke_function_arg.num_params);
	if (ioctl(conn->fd, TEE_IOC_INVOKE, &buf_data)) {
		rc = errno;
		perror("ioctl open session failed");
		goto cleanup;
	}
	convert_back_host_memrefs_with_associated_guest_memrefs(
		&host2guest_shm_id_map, command->invoke_function_arg.params,
		command->invoke_function_arg.num_params);
	sync_shared_memory_buffers_in_params_host_to_guest(
		conn, command->invoke_function_arg.params,
		command->invoke_function_arg.num_params);
	cpu_physical_memory_write(command_phys_address, command, data_length);

cleanup:
	if (command != NULL)
		g_free(command);
	if (rc) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
	}

	return rc;
}

static uint64_t handle_command_cancel_request(VirtPassthroughTeeState *s,
					      uint64_t command_phys_address,
					      uint64_t data_length,
					      uint64_t *status)
{
	int rc, host_fd;
	struct CommandCancelRequest command;

	if (data_length != sizeof(command)) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}
	cpu_physical_memory_read(command_phys_address, &command, data_length);

	if (convert_guest_fd_to_host_fd(s, command.fd, &host_fd)) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}

	if ((rc = ioctl(host_fd, TEE_IOC_CANCEL, &command.cancel_request_arg))) {
		perror("failed to cancel request");
		return rc;
	}

	return 0;
}

static uint64_t handle_command_close_session(VirtPassthroughTeeState *s,
					     uint64_t command_phys_address,
					     uint64_t data_length,
					     uint64_t *status)
{
	int rc, host_fd;
	struct CommandCloseSession command;

	if (data_length != sizeof(command)) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}
	cpu_physical_memory_read(command_phys_address, &command, data_length);

	if (convert_guest_fd_to_host_fd(s, command.fd, &host_fd)) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}

	if ((rc = ioctl(host_fd, TEE_IOC_CLOSE_SESSION,
			&command.close_session_arg))) {
		perror("failed to close session");
		return rc;
	}

	return 0;
}

static uint64_t handle_free_shared_memory_buffer(
	VirtPassthroughTeeState *s, uint64_t command_phys_address,
	uint64_t data_length, uint64_t *status)
{
	struct CommandFreeSharedMemoryBuffer command;
	struct TeeConnectionState *conn;
	struct HostSharedMemoryBuffer *shmem_to_free;

	if (data_length != sizeof(command)) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}
	cpu_physical_memory_read(command_phys_address, &command, data_length);
	conn = get_associated_tee_connection(s, command.guest_fd);
	if (conn == NULL) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}

	if (!g_hash_table_contains(conn->guest_shm_id_to_local_buffer, &command.shmem_id)) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}
	shmem_to_free = g_hash_table_lookup(conn->guest_shm_id_to_local_buffer, &command.shmem_id);
	munmap(shmem_to_free->mmap_address, shmem_to_free->size);
	close(shmem_to_free->host_fd);
	g_hash_table_remove(conn->guest_shm_id_to_local_buffer, &command.shmem_id);

	return 0;
}

static uint64_t handle_ensure_memory_buffers_are_synchronized(
	VirtPassthroughTeeState *s, uint64_t command_phys_address,
	uint64_t data_length, uint64_t *status)
{
	int buffer_fd;
	int64_t *key;
	struct TeeConnectionState *conn;
	struct CommandEnsureMemoryBuffersAreSynchronized command;
	struct HostSharedMemoryBuffer *host_buffer;
	struct tee_ioctl_shm_alloc_data alloc_ioctl_data;

	if (data_length != sizeof(command)) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}
	cpu_physical_memory_read(command_phys_address, &command, data_length);

	conn = get_associated_tee_connection(s, command.guest_fd);
	if (conn == NULL) {
		*status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
		return -EINVAL;
	}

	for (int i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
		// A negative id signals to ignore this buffer
		if (command.buffers[i].id < 0)
			continue;

		// Check if we already have allocated an associated buffer
		if (g_hash_table_contains(conn->guest_shm_id_to_local_buffer,
					  &command.buffers[i].id)) {
			continue;
		}

		// Allocate a shared memory buffer in the TEE and add it to the hashmap
		memset(&alloc_ioctl_data, 0, sizeof(alloc_ioctl_data));
		alloc_ioctl_data.size = command.buffers[i].size;
		// FIXME: despite being also an input param, the tee.h header says to set this field to zero
		//        or the ioctl will fail
		alloc_ioctl_data.flags = 0;
		buffer_fd =
			ioctl(conn->fd, TEE_IOC_SHM_ALLOC, &alloc_ioctl_data);
		// FIXME: Technically 'flag' and 'size' are input/output params, but we cannot pass them back...
		if (buffer_fd <= 0) {
			perror("failed to ioctl for alloc shared mem");
			assert(false);
			return buffer_fd;
		}

		host_buffer = g_new(struct HostSharedMemoryBuffer, 1);
		host_buffer->host_fd = buffer_fd;
		host_buffer->mmap_address =
			mmap(NULL, alloc_ioctl_data.size,
			     PROT_READ | PROT_WRITE, MAP_SHARED, buffer_fd, 0);
		// FIXME: Handle the case in which mmap fails

		host_buffer->host_id = alloc_ioctl_data.id;
		host_buffer->guest_id = command.buffers[i].id;
		host_buffer->size = command.buffers[i].size;
		host_buffer->flags = command.buffers[i].flags;
		host_buffer->guest_paddr = command.buffers[i].paddr;

		key = g_new(int64_t, 1);
		*key = command.buffers[i].id;
		g_hash_table_insert(conn->guest_shm_id_to_local_buffer, key,
				    host_buffer);
	}

	return 0;
}

struct {
	uint64_t(*callback)(VirtPassthroughTeeState*, uint64_t, uint64_t, uint64_t*);
	bool is_async; // If true, the callback will be called in a separate thread
} command_handlers[] = {
	[TP_CMD_GetVersion] = {handle_command_get_version, false},
	[TP_CMD_OpenSession] = {handle_command_open_session, false},
	[TP_CMD_InvokeFunction] = {handle_command_invoke_function, false},
	[TP_CMD_CancelRequest] = {handle_command_cancel_request, false},
	[TP_CMD_CloseSession] = {handle_command_close_session, false},
	[TP_CMD_EnsureMemoryBuffersAreSynchronized] = {handle_ensure_memory_buffers_are_synchronized, false},
	[TP_CMD_FreeSharedMemoryBuffer] = {handle_free_shared_memory_buffer, false}
};

static uint64_t start_command(VirtPassthroughTeeState *s)
{
	struct CommandWrapper wrapper;

	cpu_physical_memory_read(s->command_ptr, &wrapper, sizeof(wrapper));
	if (wrapper.cmd_id >= ARRAY_SIZE(command_handlers) || command_handlers[wrapper.cmd_id].callback == NULL) {
		assert(false);
		return -ENOTSUP;
	}

	if (!command_handlers[wrapper.cmd_id].is_async) {
		return command_handlers[wrapper.cmd_id].callback(s, wrapper.data, wrapper.data_length, &s->status);
	}

	return -ENOTSUP;
}

static uint64_t virt_passthrough_tee_read(void *opaque, hwaddr offset,
					  unsigned size)
{
	uint64_t result;
	VirtPassthroughTeeState *s = (VirtPassthroughTeeState *)opaque;

	if (offset == TP_MMIO_REG_OFFSET_OPEN_TEE) {
		s->status = TP_MMIO_REG_STATUS_FLAG_BUSY;
		result = open_new_tee_connection(s);
	} else if (offset == TP_MMIO_REG_OFFSET_OPEN_TEE + 4) {
		s->status = TP_MMIO_REG_STATUS_FLAG_BUSY;
		result = 0;
	} else if (offset == TP_MMIO_REG_OFFSET_STATUS) {
		result = s->status & 0xffffffff;
	} else if (offset == TP_MMIO_REG_OFFSET_STATUS + 4) {
		result = (s->status >> 32) & 0xffffffff;
	} else {
		printf("[qemu]: invalid read at %lx size %d\n", offset, size);
		assert(false);
	}

	s->status &= ~TP_MMIO_REG_STATUS_FLAG_BUSY;
	return result;
}

static void virt_passthrough_tee_write(void *opaque, hwaddr offset,
				       uint64_t value, unsigned size)
{
#define IS_OFFSET_FOR_REGISTER(reg_offset)                                     \
	(size == 8 && offset == (reg_offset)) ||                               \
		(size == 4 &&                                                  \
		 (offset == (reg_offset) || 4 + offset == (reg_offset)))

#define WRITE_ACCOUNTING_FOR_4BYTE_SIZES(destination, rhs)                     \
	do {                                                                   \
		if (size == 8) {                                               \
			destination = (rhs);                                   \
		} else {                                                       \
			destination &= ~(((uint64_t)0xffffffff)                \
					 << (offset % 8 == 0 ? 0 : 32));       \
			destination |= (rhs) << (offset % 8 == 0 ? 0 : 32);    \
		}                                                              \
	} while (0)

	VirtPassthroughTeeState *s = (VirtPassthroughTeeState *)opaque;

	assert(size == 4 || size == 8);

	s->status = TP_MMIO_REG_STATUS_FLAG_BUSY;

	// Special case: we only allow a single 32bit write to this register
	if (offset == TP_MMIO_REG_OFFSET_CLOSE_TEE && size == 4) {
		close_tee_connection(s, value);
	} else if (IS_OFFSET_FOR_REGISTER(TP_MMIO_REG_OFFSET_COMMAND_PTR)) {
		WRITE_ACCOUNTING_FOR_4BYTE_SIZES(s->command_ptr, value);
	} else if (offset == TP_MMIO_REG_OFFSET_SEND_COMMAND && size == 4) {
		s->return_value = start_command(s);
		if ((int)(s->return_value) < 0)
			s->status |= TP_MMIO_REG_STATUS_FLAG_ERROR;
	}

	s->status &= ~TP_MMIO_REG_STATUS_FLAG_BUSY;
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

	memory_region_init_io(&s->iomem, OBJECT(s), &virt_tee_passthrough_ops,
			      s, TYPE_VIRT_PASSTHROUGH_TEE, 0x200);
	sysbus_init_mmio(sbd, &s->iomem);

	s->status = 0;

#define INITIAL_CAPACITY 4

	s->tee_connections.capacity = INITIAL_CAPACITY;
	s->tee_connections.length = 0;
	s->tee_connections.data =
		g_new(struct TeeConnectionState, INITIAL_CAPACITY);
}

static void virt_passthrough_tee_class_init(ObjectClass *klass, void *data)
{
	DeviceClass *dc = DEVICE_CLASS(klass);

	dc->realize = virt_passthrough_tee_realize;
}

static const TypeInfo virt_passthrough_tee_info = {
	.name = TYPE_VIRT_PASSTHROUGH_TEE,
	.parent = TYPE_SYS_BUS_DEVICE,
	.instance_size = sizeof(VirtPassthroughTeeState),
	.class_init = virt_passthrough_tee_class_init,
};

static void virt_passthrough_tee_register_types(void)
{
	type_register_static(&virt_passthrough_tee_info);
}

type_init(virt_passthrough_tee_register_types)
