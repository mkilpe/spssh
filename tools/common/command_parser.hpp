#ifndef SECUREPATH_TOOLS_COMMON_COMMAND_PARSER_HEADER
#define SECUREPATH_TOOLS_COMMON_COMMAND_PARSER_HEADER

#include <optional>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <type_traits>

namespace securepath {

struct command_base {
	virtual ~command_base() {}
	virtual void parse(std::vector<std::string> const&) = 0;
	virtual void print(std::ostream&) const = 0;
};

struct command {
	command(std::string n, std::string a, std::string i, std::unique_ptr<command_base> p)
	: name(std::move(n))
	, alias(std::move(a))
	, info(std::move(i))
	, extract(std::move(p))
	{}

	std::string name;
	std::string alias;
	std::string info;
	std::unique_ptr<command_base> extract;
};

class command_parser {
public:
	command_parser(bool show_value_in_help = true)
	: show_value_in_help_(show_value_in_help)
	{}

	template<typename T>
	void add(T& var, std::string name, std::string alias, std::string info);
	template<typename T>
	void add(std::vector<T>& var, std::string name, std::string alias, std::string info);

	/// allows to have named parameter with optional value, the optional is set with default constructed T in case there is no value
	template<typename T>
	void add(std::optional<T>& var, std::string name, std::string alias, std::string info);
	void add(bool& var, std::string name, std::string alias, std::string info);
	void add(std::optional<bool>& var, std::string name, std::string alias, std::string info);

	void parse(int argc, char* args[]);
	void parse(std::istream&);
	void parse(std::string);

	void parse_file(std::string file_name);

	void print_help(std::ostream&);
private:
	template<typename Command, typename T>
	void add_impl(T& var, std::string name, std::string alias, std::string info);
	std::string parse_name(std::istream& in);
	std::string parse_quoted(std::istream& in);
	std::string parse_arg(std::istream& in);
	void parse_args(std::istream& in, std::string const& name);
private:
	std::map<std::string, std::shared_ptr<command>> commands_;
	bool const show_value_in_help_;
};

struct invalid_argument : std::runtime_error {
	using std::runtime_error::runtime_error;
};

template<typename Container>
std::ostream& print_list(std::ostream& out, Container const& c, std::string_view separator, std::string_view quote = "") {
	bool first = true;
	for(auto&& v : c) {
		if(first) {
			first = false;
			out << quote << v << quote;
		} else {
			out << separator << quote << v << quote;
		}
	}
	return out;
}

template<typename T>
struct normal_command : command_base {
	normal_command(T& v)
	: value_(v)
	{}

	virtual void parse(std::vector<std::string> const& args) {
		if(args.size() != 1) {
			std::ostringstream out;
			print_list(out, args, ",");
			throw invalid_argument("invalid amount of arguments: [" + out.str() + "]");
		}
		std::istringstream in(args[0]);
		if(!(in >> value_)) {
			throw invalid_argument("failed to interpret argument '" + args[0] + "'");
		}
	}
	virtual void print(std::ostream& o) const {
		o << value_;
	}

	T& value_;
};

template<typename T>
struct vector_command : command_base {
	vector_command(std::vector<T>& v)
	: value_(v)
	{}

	virtual void parse(std::vector<std::string> const& args) {
		value_.clear();
		for(auto&& v : args) {
			if constexpr(std::is_same_v<std::string, T>) {
				value_.push_back(v);
			} else {
				T temp;
				std::istringstream in(v);
				if(!(in >> temp)) {
					throw invalid_argument("failed to interpret argument '" + v + "'");
				}
				value_.push_back(temp);
			}
		}
	}
	virtual void print(std::ostream& o) const {
		print_list(o, value_, ", ");
	}

	std::vector<T>& value_;
};


template<typename T>
struct optional_command : command_base {
	optional_command(std::optional<T>& v)
	: value_(v)
	{}

	virtual void parse(std::vector<std::string> const& args) {
		if(args.size() > 1) {
			std::ostringstream out;
			print_list(out, args, ",");
			throw invalid_argument("invalid amount of arguments: [" + out.str() +"]");
		}

		if(args.size() == 1) {
			if constexpr(std::is_same_v<std::string, T>) {
				value_ = args[0];
			} else {
				value_.emplace();
				std::istringstream in(args[0]);
				if(!(in >> *value_)) {
					throw invalid_argument("failed to interpret argument '" + args[0] + "'");
				}
			}
		}
	}
	virtual void print(std::ostream& o) const {
		if(value_) {
			o << *value_;
		} else {
			o << "<value not set>";
		}
	}

	std::optional<T>& value_;
};


template<typename Command, typename T>
void command_parser::add_impl(T& var, std::string name, std::string alias, std::string info) {
	auto e = std::make_unique<Command>(var);
	auto p = std::make_shared<command>(name, alias, std::move(info), std::move(e));
	if(!name.empty()) {
		commands_.insert({"--"+name, p});
	}
	if(!alias.empty()) {
		commands_.insert({"-"+alias, p});
	}
}

template<typename T>
void command_parser::add(T& var, std::string name, std::string alias, std::string info) {
	add_impl<normal_command<T>>(var, std::move(name), std::move(alias), std::move(info));
}

template<typename T>
void command_parser::add(std::vector<T>& var, std::string name, std::string alias, std::string info) {
	add_impl<vector_command<T>>(var, std::move(name), std::move(alias), std::move(info));
}

template<typename T>
void command_parser::add(std::optional<T>& var, std::string name, std::string alias, std::string info) {
	add_impl<optional_command<T>>(var, std::move(name), std::move(alias), std::move(info));
}

}

#endif
