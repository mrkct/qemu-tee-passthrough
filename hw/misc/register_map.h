#ifndef REGISTER_MAP_H
#define REGISTER_MAP_H

// KEEP THIS SYNCHED WITH THE COPY IN THE QEMU REPO

#include <linux/tee.h>

#define TP_MMIO_BASE_ADDRESS 0x0b000000
#define TP_MMIO_AREA_SIZE 0x00000200

#define TP_MMIO_REG_OFFSET_OPEN_TEE 0x0
#define TP_MMIO_REG_OFFSET_CLOSE_TEE 0x8

#define TP_MMIO_REG_OFFSET_STATUS 0x10
#define TP_MMIO_REG_STATUS_FLAG_BUSY (1 << 0)
#define TP_MMIO_REG_STATUS_FLAG_ERROR (1 << 1)

#define TP_MMIO_REG_OFFSET_COMMAND_PTR 0x18
#define TP_MMIO_REG_OFFSET_SEND_COMMAND 0x20

enum CommandId {
	TP_CMD_GetVersion,
	TP_CMD_OpenSession,
	TP_CMD_InvokeFunction,
	TP_CMD_CancelRequest,
	TP_CMD_CloseSession,
	TP_CMD_EnsureMemoryBuffersAreSynchronized,
	TP_CMD_FreeSharedMemoryBuffer,

	__TP_CMD_Len
};

struct CommandWrapper {
	uint64_t cmd_id;
	uint64_t data_length;
	uint64_t data;
} __attribute__((aligned(16)));

struct CommandGetVersion {
	struct tee_ioctl_version_data version_data;
} __attribute__((aligned(16)));

struct CommandOpenSession {
	int64_t fd;
	struct tee_ioctl_open_session_arg open_session_arg;
} __attribute__((aligned(16)));

struct CommandInvokeFunction {
	int64_t fd;
	struct tee_ioctl_invoke_arg invoke_function_arg;
} __attribute__((aligned(16)));

struct CommandCancelRequest {
	int64_t fd;
	struct tee_ioctl_cancel_arg cancel_request_arg;
} __attribute__((aligned(16)));

struct CommandCloseSession {
	int64_t fd;
	struct tee_ioctl_close_session_arg close_session_arg;
} __attribute__((aligned(16)));

struct CommandEnsureMemoryBuffersAreSynchronized {
	int64_t guest_fd;
	struct {
		int64_t id;
		uint64_t size;
		uint32_t flags;
		uint64_t paddr;
	} buffers[4];
} __attribute__((aligned(16)));

struct CommandFreeSharedMemoryBuffer {
	int64_t guest_fd;
	int64_t shmem_id;
} __attribute__((aligned(16)));

#endif