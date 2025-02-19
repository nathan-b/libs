// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libsinsp/sinsp_filtercheck_group.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

#define RETURN_EXTRACT_VAR(x)  \
	do {                       \
		*len = sizeof((x));    \
		return (uint8_t*)&(x); \
	} while(0)

#define RETURN_EXTRACT_STRING(x)      \
	do {                              \
		*len = (x).size();            \
		return (uint8_t*)(x).c_str(); \
	} while(0)

static const filtercheck_field_info sinsp_filter_check_group_fields[] = {
        {PT_UINT32, EPF_NONE, PF_ID, "group.gid", "Group ID", "group ID."},
        {PT_CHARBUF, EPF_NONE, PF_NA, "group.name", "Group Name", "group name."},
};

sinsp_filter_check_group::sinsp_filter_check_group() {
	static const filter_check_info s_field_infos = {
	        "group",
	        "",
	        "Information about the user group.",
	        sizeof(sinsp_filter_check_group_fields) / sizeof(sinsp_filter_check_group_fields[0]),
	        sinsp_filter_check_group_fields,
	        filter_check_info::FL_NONE,
	};
	m_info = &s_field_infos;
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_group::allocate_new() {
	return std::make_unique<sinsp_filter_check_group>();
}

uint8_t* sinsp_filter_check_group::extract_single(sinsp_evt* evt,
                                                  uint32_t* len,
                                                  bool sanitize_strings) {
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL) {
		return NULL;
	}

	switch(m_field_id) {
	case TYPE_GID:
		m_gid = tinfo->m_gid;
		RETURN_EXTRACT_VAR(m_gid);
	case TYPE_NAME: {
		auto group = tinfo->get_group();
		m_name = group->name;
		RETURN_EXTRACT_STRING(m_name);
	}
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
