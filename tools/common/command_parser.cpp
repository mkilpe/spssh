#include "command_parser.hpp"
#include <fstream>

namespace securepath {

void command_parser::parse(int argc, char* args[]) {
	std::string s;
	for(int i = 1; i != argc; ++i) {
		if(i > 1) {
			s += " ";
		}
		std::string arg = args[i];
		if(arg.find(' ') != std::string::npos) {
			arg = '"' + arg + '"';
		}
		s += arg;
	}
	parse(s);
}

void command_parser::parse(std::string s) {
	std::istringstream in(s);
	parse(in);
}

std::string command_parser::parse_name(std::istream& in) {
	std::string s;
	in >> s;
	return s;
}

std::string command_parser::parse_quoted(std::istream& in) {
	std::string s;
	in.ignore(); //the start of quote
	for(; in.peek() != '"'; ) {
		s += in.get();
	}
	in.ignore();
	return s;
}

std::string command_parser::parse_arg(std::istream& in) {
	std::string s;
	if(in.peek() == '"') {
		s = parse_quoted(in);
	} else {
		in >> s;
	}
	return s;
}

void command_parser::parse_args(std::istream& in, std::string const& name) {
	std::vector<std::string> args;
	
	for(;in >> std::ws && in.peek() != '-';) {
		std::string a = parse_arg(in);
		if(!a.empty())  {
			args.push_back(std::move(a));
		}
	}
	
	auto it = commands_.find(name);
	if(it == commands_.end()) {
		throw invalid_argument("no parameter named '" + name + "'");
	}
	it->second->extract->parse(args);
}

void command_parser::parse(std::istream& in) {
	for(; in >> std::ws; ) {
		char c = in.peek();
		if(c == '-') {
			parse_args(in, parse_name(in));
		} else {
			parse_arg(in); //for now just ignore positionals
		}
	}
}

namespace {

struct print_align {
	print_align(std::ostream& out, std::size_t s = 0)
	: out_(out)
	{
		if(s) {
			align(s);
		}
	}

	~print_align () {
		out_ << temp_out_.str();
	}

	template<typename T>
	print_align& operator<<(T const& v) {
		temp_out_ << v;
		return *this;
	}

	print_align& align(std::size_t s) {
		std::string str = temp_out_.str().substr(0, s);
		out_ << str << std::string(s-str.size(), ' ');
		temp_out_.clear();
		temp_out_.str("");
		return *this;
	}

	std::ostringstream temp_out_;
	std::ostream& out_;
};

}

void command_parser::print_help(std::ostream& out) {
	for(auto&& v : commands_) {
		if(v.first.substr(0, 2) == "--") {
			auto const& info = *v.second;
			std::string alias;
			if(!info.alias.empty()) {
				alias = ", -" + info.alias;
			}

			(print_align(out) << "--" << info.name << alias).align(50) << " " << info.info;

			if(show_value_in_help_) {
				std::ostringstream extract_out;
				info.extract->print(extract_out);
				std::string eout = extract_out.str();

				if(!eout.empty()) {
					out << " (" + eout + ")";
				}
			}
			out << std::endl;
		}
	}
}

void command_parser::parse_file(std::string file_name) {
	std::ifstream is(file_name);
	std::string line;
	while(std::getline(is, line)) {
		parse(line);
	}
}

struct bool_command : command_base {
	bool_command(bool& v)
	: value_(v)
	{}

	virtual void parse(std::vector<std::string> const&) {
		value_ = true;
	}
	virtual void print(std::ostream& o) const {
		o << (value_ ? "true" : "false");
	}

	bool& value_;
};

void command_parser::add(bool& var, std::string name, std::string alias, std::string info) {
	add_impl<bool_command>(var, std::move(name), std::move(alias), std::move(info));
}

template<bool Value>
struct optional_bool_command : command_base {
	optional_bool_command(std::optional<bool>& v)
	: value_(v)
	{}

	virtual void parse(std::vector<std::string> const&) {
		value_ = Value;
	}

	virtual void print(std::ostream& o) const {
		if(value_) {
			o << (*value_ ? "true" : "false");
		}
	}

	std::optional<bool>& value_;
};

void command_parser::add(std::optional<bool>& var, std::string name, std::string alias, std::string info) {
	add_impl<optional_bool_command<true>>(var, name, alias, info);
	add_impl<optional_bool_command<false>>(var, "no-" + name, alias.empty() ? alias : "no-" + alias, "Unset: " + info);
}

}
