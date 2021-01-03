/*
Copyright (C) 2013-2020 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

//
// This is the opaque pointer to the state of a source plugin.
// It points to any data that might be needed plugin-wise. It is 
// allocated by init() and must be destroyed by destroy().
//
typedef void src_plugin_t;

//
// This is the opaque pointer to the state of an open instance of the source 
// plugin.
// It points to any data that is needed while a capture is running. It is 
// allocated by open() and must be destroyed by close().
//
typedef void src_instance_t;

//
// This is the interface of a scap source plugin
//
typedef struct
{
	//
	// Initialize the plugin and, if needed, allocate its state.
	// This method is optional.
	//
	src_plugin_t* (*init)(char* config, int32_t* rc);
	//
	// Return a string with the error that was latest generated by the plugin.
	//
	char* (*get_last_error)();
	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// This method is optional.
	//
	void (*destroy)(src_plugin_t* s);
	//
	// Return the unique ID of the plugin. 
	// EVERY PLUGIN MUST OBTAIN AN OFFICIAL ID FROM THE FALCO ORGANIZATION,
	// OTHERWISE IT WON'T PROPERLY WITH OTHER PLUGINS.
	// This method is required.
	//
	uint32_t (*get_id)();
	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// This method is required.
	//
	char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// This method is required.
	//
	char* (*get_description)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in falco rules and sysdig filters.
	// This method returns a string with the list of fields encoded as a json
	// array.
	// This method is required.
	//
	char* (*get_fields)();
	//
	// Open the source and start a capture.
	// This method is required.
	//
	src_instance_t* (*open)(src_plugin_t* s, int32_t* rc);
	//
	// Open the source and start a capture.
	// This method is required.
	//
	void (*close)(src_plugin_t* s, src_instance_t* h);
	//
	// Return the next event.
	// This method is required.
	//
	int32_t (*next)(src_plugin_t* s, src_instance_t* h, uint8_t** data, uint32_t* datalen);
	//
	// Return a text representation of an event generated by this source plugin.
	// The function receives data and datalen produced by scap_src.next().
	// This is used, for example, by sysdig to print a line for the given event.
	// This method is required.
	//
	char* (*event_to_string)(uint8_t* data, uint32_t datalen);
	//
	// Extract a.string filter value from an event.
	// - evtnum is the number of the event that is bein processed
	// - id is the numeric identifier of the field to extract. It corresponds to the
	// position of the field in the array returned by get_fields().
	// - arg is the field argument, if an argument has been specified for the field,
	//   otherwise it's NULL. For example:
	//    * if the field specified by the user is foo.bar[pippo], arg will be the 
	//      string "pippo"
	//    * if the field specified by the user is foo.bar, arg will be NULL
	// - data and datalen contain the event information to be decoded.
	// This method is required.
	//
	char* (*extract_as_string)(uint64_t evtnum, uint32_t id, char* arg, uint8_t* data, uint32_t datalen);

	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	src_plugin_t* state;
	src_instance_t* handle;
	uint32_t id;
} source_plugin_info;
