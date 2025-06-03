#pragma once

#include <cstdint>
#include <list>
#include <string>
#include <unordered_map>
#include <vector>

#include <sinsp.h>

enum evt_class {
	EVT_CLASS_UNKNOWN = 0,
	EVT_CLASS_IO,    // I/O events
	EVT_CLASS_NET,   // Network state changes
	EVT_CLASS_FILE,  // File system state changes
	EVT_CLASS_PROC,  // Process and thread state changes
	EVT_CLASS_OTHER  // Other types of events
};

struct capture_evt {
	uint64_t ts_ns;         // Timestamp, in nanoseconds from epoch
	uint16_t cpu;           // the CPU that generated the event
	uint16_t type;          // Event type (ppm_event_code from ppm_events_public.h)
	evt_class event_class;  // Class of the event (e.g., I/O, network, file, process)
	sinsp_evt* pevt;        // Pointer to the raw event
};

/**
 * Manages the event list from a capture file.
 *
 * Events are stored per-CPU. The list of events is further broken down by
 * timestamp. A cpu_event_list is indexed by timestamp, where each slot in the
 * vector represents one second. So evt_list[0] contains all events that occurred
 * in the first second of the capture file, and so on.
 */
class processed_events {
public:
	using cpu_event_list = std::vector<std::list<capture_evt>>;

	processed_events() = default;
	~processed_events() = default;

	/**
	 * @brief Add an event to the list of events for a specific CPU.
	 */
	void add_event(const capture_evt& evt);

	/**
	 * @brief Get the list of events for a specific CPU.
	 */
	cpu_event_list get_events(uint32_t cpu);

	/**
	 * @brief Get the number of CPUs that have events in the capture file.
	 */
	uint32_t num_cpus() const { return m_events_by_cpu.size(); }

private:
	/**
	 * @brief Calculate the number of seconds into the capture for a given timestamp.
	 *
	 * Calculates how many seconds into the capture the timestamp is.
	 *
	 * If there is an error, returns 0
	 */
	uint64_t seconds_into_capture(uint64_t ts_ns) const;

	bool m_events_loaded = false;
	uint64_t m_start_ts_ns = 0;  // Start timestamp of the capture in nanoseconds
	std::unordered_map<uint32_t, cpu_event_list> m_events_by_cpu;
};
