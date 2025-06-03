#include <iostream>
#include <fstream>
#include <string>

#include "capture_reader.h"
#include "sinsp.h"
#include "event.h"

evt_class classify(sinsp_evt* evt) {
	uint16_t type = PPME_MAKE_ENTER(evt->get_type());
	switch(type) {
	case PPME_SYSCALL_READ_E:
	case PPME_SOCKET_RECV_E:
	case PPME_SOCKET_RECVMSG_E:
	case PPME_SOCKET_RECVMMSG_E:
	case PPME_SOCKET_RECVFROM_E:
	case PPME_SYSCALL_WRITE_E:
	case PPME_SOCKET_SEND_E:
	case PPME_SOCKET_SENDMSG_E:
	case PPME_SOCKET_SENDMMSG_E:
	case PPME_SOCKET_SENDTO_E:
		return EVT_CLASS_IO;
	case PPME_SYSCALL_OPEN_E:
	case PPME_SYSCALL_OPENAT_E:
	case PPME_SYSCALL_OPENAT_2_E:
	case PPME_SYSCALL_OPENAT2_E:
	case PPME_SYSCALL_OPEN_BY_HANDLE_AT_E:
	case PPME_SYSCALL_CLOSE_E:
		return EVT_CLASS_FILE;
	case PPME_SOCKET_SOCKET_E:
	case PPME_SOCKET_ACCEPT_E:
	case PPME_SOCKET_ACCEPT_5_E:
	case PPME_SOCKET_ACCEPT4_E:
	case PPME_SOCKET_ACCEPT4_5_E:
	case PPME_SOCKET_ACCEPT4_6_E:
	case PPME_SOCKET_BIND_E:
	case PPME_SOCKET_CONNECT_E:
	case PPME_SOCKET_SHUTDOWN_E:
	case PPME_SOCKET_LISTEN_E:
		return EVT_CLASS_NET;
	case PPME_SYSCALL_EXECVE_8_E:
	case PPME_SYSCALL_EXECVE_13_E:
	case PPME_SYSCALL_EXECVE_14_E:
	case PPME_SYSCALL_EXECVE_15_E:
	case PPME_SYSCALL_EXECVE_16_E:
	case PPME_SYSCALL_EXECVE_17_E:
	case PPME_SYSCALL_EXECVE_18_E:
	case PPME_SYSCALL_EXECVE_19_E:
	case PPME_SYSCALL_CLONE_11_E:
	case PPME_SYSCALL_CLONE_16_E:
	case PPME_SYSCALL_CLONE_17_E:
	case PPME_SYSCALL_CLONE_20_E:
	case PPME_SYSCALL_FORK_E:
	case PPME_SYSCALL_FORK_17_E:
	case PPME_SYSCALL_FORK_20_E:
		return EVT_CLASS_PROC;
	default:
		break;
	}
	return EVT_CLASS_OTHER;
}

bool read_capture(const std::string& filename, processed_events& pe) {
	sinsp inspector;
	inspector.open_savefile(filename);

	if(!inspector.is_capture()) {
		std::cerr << "Failed to open capture file: " << filename << "\n";
		return false;
	}

	while(true) {
		sinsp_evt* evt = nullptr;
		int ret = inspector.next(&evt);
		if(ret == SCAP_EOF) {
			break;  // End of file
		} else if(ret != SCAP_SUCCESS) {
			std::cerr << "Error reading events: " << inspector.getlasterr() << "\n";
			return false;
		}
		if(evt == nullptr) {
			continue;  // No event, continue to next
		}

		capture_evt cap_evt;
		cap_evt.ts_ns = evt->get_ts();
		cap_evt.cpu = evt->get_cpuid();
		cap_evt.type = evt->get_type();
		cap_evt.event_class = classify(evt);
		cap_evt.pevt = evt;

		pe.add_event(cap_evt);
	}

	return true;
}

int main(int argc, char** argv) {
	if(argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <capture_file>\n";
		return 1;
	}
	std::string filename = argv[1];

	processed_events pe;
	if(!read_capture(filename, pe)) {
		std::cerr << "Failed to read capture file: " << filename << "\n";
		return 1;
	}
	std::cout << "Capture file processed successfully.\n";

	uint32_t num_cpus = pe.num_cpus();
	for(uint32_t i = 0; i < num_cpus; ++i) {
		auto events = pe.get_events(i);
		std::cout << "CPU " << i << " has " << events.size() << " seconds worth of events.\n";
		for(uint32_t j = 0; j < events.size(); ++j) {
			std::cout << "\t" << j << ": " << events[j].size() << " events\n";
		}
	}

	return 0;
}
