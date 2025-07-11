#include "event_generator.h"

#include <iostream>
#include <list>
#include <random>

#include "capture_reader.h"
#include "event.h"
#include "sinsp.h"

event_builder::event_builder(uint32_t cpu_id, uint32_t seed)
	: m_cpu_id(cpu_id),
	  m_gen(seed)
{
}

std::list<lg_event> event_builder::build_events(const std::list<capture_evt>& evt_list,
                                                uint32_t num_events) const
{
	constexpr uint64_t ns_per_sec = 1000000000;
	constexpr uint64_t ns_per_us = 1000;

	std::list<lg_event> events;
	uint64_t base_ts = 0;

	std::cout << "build_events for cpu " << m_cpu_id
	          << " with " << evt_list.size() << " events and target of "
	          << num_events << " events.\n";

	// Return empty list if no events or zero requested
	if(evt_list.empty() || num_events == 0) {
		return events;
	}

	// Step 1: Determine the distribution of event classes.
	uint32_t class_percents[EVT_CLASS_MAX] = {0}; // What percent of events are in each class
	{
		// Break down the existing event list by class
		std::unordered_map<evt_class, uint32_t> event_counts;
		for(const auto& evt : evt_list) {
			++event_counts[evt.event_class];
			if (base_ts == 0) {
				base_ts = evt.ts_ns; // Set the base timestamp to the first event's timestamp
			}
		}

		// Determine how many target events fall into each class.
		uint32_t check_events = 0;
		for (const auto& [ec, count] : event_counts) {
			uint32_t percent = (count * 100) / evt_list.size();
			class_percents[ec] = percent;
			check_events += class_percents[ec];
		}
		// If this doesn't add up to 100% (due to rounding), fix it up in post
		uint32_t curr = 0;
		if (check_events == 0) {
			// This shouldn't happen, but the logic below will break if it does so check now
			return events;
		}
		while (check_events < 100) {
			if (class_percents[curr] > 0) {
				++class_percents[curr];
				++check_events;
			}
			curr = (curr + 1) % EVT_CLASS_MAX;
		}
	}

	// Step 2: Determine the event rate.
	//         This currently produces an even distribution of events across the entire second.
	const double evts_per_us = static_cast<double>(num_events) / 1000000.0;
	double curr_evts = 0.0;

	// Step 3: Generate the events.
	//         Determine how many events to send every microsecond, then generate events based on
	//         the class distribution.
	std::uniform_int_distribution<int> dist(0, 99);
	uint32_t counter = 0;
	for (uint64_t curr_ts_offset = 0; curr_ts_offset < ns_per_sec; curr_ts_offset += ns_per_us) {
		counter += 1;
		curr_evts += evts_per_us;
		uint32_t curr_evt_offset = 0;
		while (curr_evts > 1.0) { // Generate events
			uint32_t val = dist(m_gen);
			uint32_t curr_pct = 0;
			for (int j = 0; j < EVT_CLASS_MAX; ++j) {
				curr_pct += class_percents[j];
				if (val < curr_pct) {
					lg_event new_event = create_event(base_ts + curr_ts_offset + curr_evt_offset, static_cast<evt_class>(j));
					events.push_back(new_event);
					break;
				}
			}
			curr_evts -= 1.0;
			curr_evt_offset += 10; // One event every 10ns
		}
	}

	return events;
}

static ppm_event_code get_code_from_class(evt_class event_class)
{
	// TODO: Should generate both enter and exit events until we only send exit events
	// TODO: This function needs to be a lot smarter
	std::unordered_map<evt_class, std::vector<ppm_event_code>> class_to_code = {
		{EVT_CLASS_IO, {PPME_SYSCALL_READ_X,
		                PPME_SYSCALL_WRITE_X,
						PPME_SOCKET_RECV_X,
						PPME_SOCKET_SEND_X,
						PPME_SOCKET_RECVMSG_X,
						PPME_SOCKET_SENDMSG_X,
						PPME_SOCKET_RECVMMSG_X,
						PPME_SOCKET_SENDMMSG_X,
						PPME_SOCKET_RECVFROM_X,
						PPME_SOCKET_SENDTO_X}},
		{EVT_CLASS_NET, {PPME_SOCKET_SOCKET_X,
		                     PPME_SOCKET_ACCEPT_X,
		                     PPME_SOCKET_BIND_X,
		                     PPME_SOCKET_CONNECT_X,
		                     PPME_SOCKET_SHUTDOWN_X,
		                     PPME_SOCKET_LISTEN_X}},
		{EVT_CLASS_FILE, {PPME_SYSCALL_OPEN_X,
		                  PPME_SYSCALL_OPENAT_X,
		                  PPME_SYSCALL_OPENAT_2_X,
		                  PPME_SYSCALL_OPENAT2_X,
		                  PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
		                  PPME_SYSCALL_CLOSE_X}},
		{EVT_CLASS_PROC, {PPME_SYSCALL_EXECVE_8_X,
		                     PPME_SYSCALL_EXECVE_13_X,
		                     PPME_SYSCALL_EXECVE_14_X,
		                     PPME_SYSCALL_EXECVE_15_X,
		                     PPME_SYSCALL_EXECVE_16_X,
		                     PPME_SYSCALL_EXECVE_17_X,
		                     PPME_SYSCALL_EXECVE_18_X,
		                     PPME_SYSCALL_EXECVE_19_X,
		                     PPME_SYSCALL_CLONE_11_X,
		                     PPME_SYSCALL_CLONE_16_X,
		                     PPME_SYSCALL_CLONE_17_X,
		                     PPME_SYSCALL_CLONE_20_X,
		                     PPME_SYSCALL_FORK_X,
		                     PPME_SYSCALL_FORK_17_X,
		                     PPME_SYSCALL_FORK_20_X}},
		{EVT_CLASS_OTHER, {PPME_SYSCALL_FUTEX_X}} // TODO: Need more here
	};

	std::unordered_map<evt_class, uint32_t> class_index = {
		{EVT_CLASS_IO, 0},
		{EVT_CLASS_NET, 0},
		{EVT_CLASS_FILE, 0},
		{EVT_CLASS_PROC, 0},
		{EVT_CLASS_OTHER, 0}
	};
	ppm_event_code code = class_to_code[event_class][class_index[event_class]];
	class_index[event_class] = (class_index[event_class] + 1) % class_to_code[event_class].size();
	return code;
}

lg_event event_builder::create_event(uint64_t ts_ns, evt_class event_class) const
{
	lg_event new_event;
	new_event.cpu = m_cpu_id;
	new_event.ts_ns = ts_ns;
	new_event.type = get_code_from_class(event_class);
	return new_event;
}

