
#include "transport_base.hpp"

namespace securepath::ssh {

bool send_payload(transport_base& base, const_span payload) {
	base.call_context().log.log(logger::debug_trace, "SSH sending payload");

	auto rec = base.alloc_out_packet(payload.size());
	if(rec) {
		copy(payload, rec->data);
		return base.write_alloced_out_packet(*rec);
	} else {
		base.set_error(spssh_memory_error, "Could not allocate buffer for sending payload");
	}

	return false;
}

}
