#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <unordered_map>

#include "capture_reader.h"
#include "event_generator.h"
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

void gen_events_for_cpu(uint32_t cpuid,
                        std::vector<std::list<capture_evt>> cpu_events,
						const std::vector<uint32_t>& counts_per_second,
						uint32_t seed) {
	event_builder eb(cpuid, seed);
	uint32_t tick = 0;
	for(const auto& one_second : cpu_events) {
		if(one_second.empty()) {
			++tick;
			continue;  // No events for this second
		}
		auto lg_events = eb.build_events(one_second, counts_per_second[tick]);
		std::cout << "Generated " << lg_events.size() << " events for CPU " << cpuid
		          << " in second " << tick++ << "\n";
	}
}

/**
 * @brief Read a capture file and store its events.
 *
 * @return Number of events processed (0 indicates failure).
 */
uint64_t read_capture(const std::string& filename, processed_events& pe) {
	sinsp inspector;
	uint64_t num_events = 0;
	inspector.open_savefile(filename);

	if(!inspector.is_capture()) {
		std::cerr << "Failed to open capture file: " << filename << "\n";
		return 0;
	}

	while(true) {
		sinsp_evt* evt = nullptr;
		int ret = inspector.next(&evt);
		if(ret == SCAP_EOF) {
			break;  // End of file
		} else if(ret != SCAP_SUCCESS) {
			std::cerr << "Error reading events: " << inspector.getlasterr() << "\n";
			return 0;
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
		++num_events;
	}

	return num_events;
}

int main(int argc, char** argv) {
	// TODO: Do some better command line parsing...
	if(argc < 3) {
		std::cerr << "Usage: " << argv[0] << " <capture_file> <num_events>\n";
		return 1;
	}
	std::string filename = argv[1];
	uint32_t event_count_target = std::stoi(argv[2]);

	//
	// Phase 1: Read the capture file and process events
	//
	processed_events pe;
	uint64_t total_events = read_capture(filename, pe);
	if(total_events == 0) {
		std::cerr << "Failed to read capture file: " << filename << "\n";
		return 1;
	}
	std::cout << "Capture file processed successfully (" << total_events << " events).\n";

	// Calculate the percentage of total events per second each CPU is processing
	//   map[cpu_id] => vector[second] => number of events for that second on that cpu
	std::unordered_map<uint32_t, std::vector<uint32_t>> cpu_event_distribution;
	//   vector[seconds_into_capture] => target number of events for that second
	std::vector<uint32_t> distribution_over_time;
	uint32_t num_cpus = pe.num_cpus();
	{
		uint32_t num_seconds = pe.num_seconds();
		for(uint32_t second = 0; second <= num_seconds; ++second) {
			// Pass 1: Calculate the total events this second
			uint32_t sec_events = 0;
			for(uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
				auto cpu_events = pe.get_events(cpu);
				if(second >= cpu_events.size()) {
					continue;  // No events for this second
				}
				sec_events += cpu_events[second].size();
			}
			uint64_t percent = (sec_events * 100) / total_events;
			distribution_over_time.push_back(event_count_target * percent / 100);
			if (sec_events == 0) {
				continue;  // No events for this second across all CPUs
			}
			// Pass 2: Calculate the percentage of events for each CPU
			for(uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
				auto cpu_events = pe.get_events(cpu);
				if(second >= cpu_events.size()) {
					continue;  // No events for this second
				}
				uint32_t my_events = cpu_events[second].size();
				percent = (my_events * 100) / sec_events;
				cpu_event_distribution[cpu].push_back(percent * distribution_over_time[second] / 100);
			}
		}
	}

	// Print some basic stuff just for debugging
	for(uint32_t i = 0; i < num_cpus; ++i) {
		auto cpu_events = pe.get_events(i);
		std::cout << "CPU " << i << " has " << cpu_events.size() << " seconds worth of events.\n";
		for (uint32_t second = 0; second < cpu_events.size(); ++second) {
			std::cout << "  Second " << second << ": " << cpu_events[second].size() << " events.\n";
		}
	}
	for (uint32_t i = 0; i < distribution_over_time.size(); ++i) {
		std::cout << "Second " << i << ": " << distribution_over_time[i] << " events expected.\n";
		for (const auto& [cpu, counts] : cpu_event_distribution) {
			if (i < counts.size()) {
				std::cout << "  CPU " << cpu << ": " << counts[i] << " events expected.\n";
			}
		}
	}

	//
	// Phase 2: Build events for each CPU
	//
	std::list<std::thread> threads;
	for(uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
		auto cpu_events = pe.get_events(cpu);
		if(cpu_events.empty()) {
			continue;  // No events for this CPU
		}
		// TODO: Allow seed to be configurable (right now it's fixed for reproducibility)
		threads.emplace_back(gen_events_for_cpu, cpu, cpu_events, std::ref(cpu_event_distribution[cpu]), 42);
	}

	//
	// Phase 3: Wait for all threads to finish
	//
	for(auto& t : threads) {
		if(t.joinable()) {
			t.join();
		}
	}

	return 0;
}
