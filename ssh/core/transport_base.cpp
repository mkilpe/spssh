
#include "transport_base.hpp"

namespace securepath::ssh {

bool transport_base::send_payload(const_span payload) {
	call_context().log.log(logger::debug_trace, "SSH sending payload");

	auto rec = alloc_out_packet(payload.size());
	if(rec) {
		copy(payload, rec->data);
		return write_alloced_out_packet(*rec);
	} else {
		set_error(spssh_memory_error, "Could not allocate buffer for sending payload");
	}

	return false;
}

}
