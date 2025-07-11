#pragma once

#include <list>
#include <random>

#include "capture_reader.h"

/**
 * A single event for the load generator to perform.
 */
struct lg_event {
	uint64_t ts_ns;  // Timestamp for the new event
	uint16_t cpu;    // the CPU that generated the event
	uint16_t type;   // Event type (ppm_event_code from ppm_events_public.h)
};

/**
 * Processes the list of events from a capture file for a single CPU.
 */
class event_builder {
public:
	event_builder(uint32_t cpu_id, uint32_t seed);
	~event_builder() = default;

	/**
	 * @brief Get the CPU ID for which this event list is created.
	 */
	uint32_t get_cpu_id() const { return m_cpu_id; }

	/**
	 * @brief Build the event list given a capture file's event list.
	 *
	 * This function processes the list of capture events and uses them to
	 * create a list of load generator events. The events are created as
	 * follows:
	 * - The percentages of each event type are calculated for the given
	 *   second.
	 * - The events are created with timestamps and types that mirror the
	 *   distribution of events from the capture file.
	 *
	 * Input is the list of events for the given second and CPU, and the
	 * number of events to generate.
	 */
	std::list<lg_event> build_events(const std::list<capture_evt>& evt_list,
	                                 uint32_t num_events) const;

private:
	/**
	 * @brief Create a single event from the given class.
	 */
	lg_event create_event(uint64_t ts_ns, evt_class event_class) const;

	uint32_t m_cpu_id;  // CPU ID for which this event list is created
	mutable std::mt19937 m_gen; // Random number generator for event distribution
};
