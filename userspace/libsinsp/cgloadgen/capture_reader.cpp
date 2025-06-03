#include "capture_reader.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <driver/ppm_events_public.h>
#include <sinsp.h>

void processed_events::add_event(const capture_evt& evt) {
	if(!m_events_loaded) {
		m_events_loaded = true;
	}
	if(m_start_ts_ns == 0) {
		m_start_ts_ns = evt.ts_ns;  // Set the start timestamp to the first event's timestamp
	}

	auto& cpu_list = m_events_by_cpu[evt.cpu];
	auto capture_second = seconds_into_capture(evt.ts_ns);
	if(cpu_list.size() <= capture_second) {
		cpu_list.resize(capture_second + 1);
	}
	cpu_list[capture_second].push_back(evt);
}

uint64_t processed_events::seconds_into_capture(uint64_t ts_ns) const {
	if(m_start_ts_ns == 0 || ts_ns < m_start_ts_ns) {
		return 0;
	}
	ts_ns -= m_start_ts_ns;     // Adjust timestamp to be relative to capture start
	return ts_ns / 1000000000;  // Convert nanoseconds to seconds
}

processed_events::cpu_event_list processed_events::get_events(uint32_t cpu) {
	auto it = m_events_by_cpu.find(cpu);
	if(it != m_events_by_cpu.end()) {
		return it->second;
	}
	return cpu_event_list();  // Return an empty list if no events for this CPU
}
