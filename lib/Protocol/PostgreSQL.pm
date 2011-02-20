package Protocol::PostgreSQL;
# ABSTRACT: PostgreSQL wire protocol
use strict;
use warnings;

our $VERSION = '0.004';

=head1 NAME

Protocol::PostgreSQL - support for the PostgreSQL wire protocol

=head1 VERSION

version 0.004

=head1 SYNOPSIS

 use strict; use warnings;
 package PostgreSQL::Client;
 use parent q{Protocol::PostgreSQL::Client};

 sub new { my $self = shift->SUPER::new(@_); $self->{socket} = $self->connect(...); $self }
 sub on_send_request { shift->socket->send(@_) }
 sub socket { shift->{socket} }

 sub connect { ... } # provide a method to connect to the server
 sub incoming { shift->socket->read(@_) } # provide a method which passes on data from server

 package main;
 my $client = PostgreSQL::Client->new(user => ..., server => ..., database => ...);
 $client->simple_query(sql => q{select * from table}, on_data_row => sub {
 	my ($client, %args) = @_;
	my @cols = $args{row};
	print join(',', @cols) . "\n";
 });

=head1 DESCRIPTION

Provides protocol-level support for PostgreSQL 7.4+, as defined in L<http://www.postgresql.org/docs/current/static/protocol.html>.

=head2 CALLBACKS

The following callbacks can be provided either as parameters to L</new> or as methods in subclasses:

=over 4

=item * on_send_request - Called each time there is a new message to be sent to the other side of the connection.

=item * on_authenticated - Called when authentication is complete

=item * on_copy_data - we have received data from an ongoing COPY request

=item * on_copy_complete - the active COPY request has completed

=back

For the client, the following additional callbacks are available:

=over 4

=item * on_request_ready - the server is ready for the next request

=item * on_bind_complete - a Bind request has completed

=item * on_close_complete - the Close request has completed

=item * on_command_complete - the requested command has finished, this will typically be followed by an on_request_ready event

=item * on_copy_in_response - indicates that the server is ready to receive COPY data

=item * on_copy_out_response - indicates that the server is ready to send COPY data

=item * on_copy_both_response - indicates that the server is ready to exchange COPY data (for replication)

=item * on_data_row - data from the current query

=item * on_empty_query - special-case response when sent an empty query, can be used for 'ping'. Typically followed by on_request_ready

=item * on_error - server has raised an error

=item * on_function_call_result - results from a function call

=item * on_no_data - indicate that a query returned no data, typically followed by on_request_ready

=item * on_notice - server has sent us a notice

=item * on_notification - server has sent us a NOTIFY

=item * on_parameter_description - parameters are being described

=item * on_parameter_status - parameter status...

=item * on_parse_complete - parsing is done

=item * on_portal_suspended - the portal has been suspended, probably hit the row limit

=item * on_ready_for_query - we're ready for queries

=item * on_row_description - descriptive information about the rows we're likely to be seeing shortly

=back

And the server can send these events:

=over 4

=item * on_copy_fail - the frontend is indicating that the copy has failed

=item * on_describe - request for something to be described

=item * on_execute - request execution of a given portal

=item * on_flush - request flush

=item * on_function_call - request execution of a given function

=item * on_parse - request to parse something

=item * on_password - password information

=item * on_query - simple query request

=item * on_ssl_request - we have an SSL request

=item * on_startup_message - we have an SSL request

=item * on_sync - sync request

=item * on_terminate - termination request

=back

=cut

use Digest::MD5 ();
use Time::HiRes ();
use POSIX qw{strftime};
use Protocol::PostgreSQL::RowDescription;
use Protocol::PostgreSQL::Statement;

# Currently v3.0, which is used in PostgreSQL 7.4+
use constant PROTOCOL_VERSION	=> 0x00030000;

# Types of authentication response
my %AUTH_TYPE = (
	0	=> 'AuthenticationOk',
	2	=> 'AuthenticationKerberosV5',
	3	=> 'AuthenticationCleartextPassword',
	5	=> 'AuthenticationMD5Password',
	6	=> 'AuthenticationSCMCredential',
	7	=> 'AuthenticationGSS',
	9	=> 'AuthenticationSSPI',
	8	=> 'AuthenticationGSSContinue',
);

# Transaction states the backend can be in
my %BACKEND_STATE = (
	I	=> 'idle',
	T	=> 'transaction',
	E	=> 'error'
);

# used for error and notice responses
my %NOTICE_CODE = (
	S	=> 'severity',
	C	=> 'code',
	M	=> 'message',
	D	=> 'detail',
	H	=> 'hint',
	P	=> 'position',
	p	=> 'internal_position',
	q	=> 'internal_query',
	W	=> 'where',
	F	=> 'file',
	L	=> 'line',
	R	=> 'routine'
);

# Mapping from name to backend message code (single byte)
our %MESSAGE_TYPE_BACKEND = (
	AuthenticationRequest	=> 'R',
	BackendKeyData		=> 'K',
	BindComplete		=> '2',
	CloseComplete		=> '3',
	CommandComplete		=> 'C',
	CopyData		=> 'd',
	CopyDone		=> 'c',
	CopyInResponse		=> 'G',
	CopyOutResponse		=> 'H',
	CopyBothResponse	=> 'W',
	DataRow			=> 'D',
	EmptyQueryResponse	=> 'I',
	ErrorResponse		=> 'E',
	FunctionCallResponse	=> 'V',
	NoData			=> 'n',
	NoticeResponse		=> 'N',
	NotificationResponse	=> 'A',
	ParameterDescription	=> 't',
	ParameterStatus		=> 'S',
	ParseComplete		=> '1',
	PortalSuspended		=> 's',
	ReadyForQuery		=> 'Z',
	RowDescription		=> 'T',
);
our %BACKEND_MESSAGE_CODE = reverse %MESSAGE_TYPE_BACKEND;

# Mapping from name to frontend message code (single byte)
our %MESSAGE_TYPE_FRONTEND = (
	Bind			=> 'B',
	Close			=> 'C',
	CopyData		=> 'd',
	CopyDone		=> 'c',
	CopyFail		=> 'f',
	Describe		=> 'D',
	Execute			=> 'E',
	Flush			=> 'H',
	FunctionCall		=> 'F',
	Parse			=> 'P',
	PasswordMessage		=> 'p',
	Query			=> 'Q',
#	SSLRequest		=> '',
#	StartupMessage		=> '',
	Sync			=> 'S',
	Terminate		=> 'X',
);
our %FRONTEND_MESSAGE_CODE = reverse %MESSAGE_TYPE_FRONTEND;

# Defined message handlers for outgoing frontend messages
our %FRONTEND_MESSAGE_BUILDER = (
# Bind parameters to an existing prepared statement
	Bind => sub {
		my $self = shift;
		my %args = @_;

		$args{param} ||= [];
		my $param = '';
		my $count = scalar @{$args{param}};
		foreach my $p (@{$args{param}}) {
			if(!defined $p) {
				$param .= pack('N1', 0xFFFFFFFF);
			} else {
				$param .= pack('N1a*', length($p), $p);
			}
		}
		my $msg = pack('Z*Z*n1n1a*n1',
			defined($args{portal}) ? $args{portal} : '',
			defined($args{statement}) ? $args{statement} : '',
			0,		# Parameter types
			$count,		# Number of bound parameters
			$param,		# Actual parameter values
			0		# Number of result column format definitions (0=use default text format)
		);
		return $self->_build_message(
			type	=> 'Bind',
			data	=> $msg,
		);
	},
	CopyData => sub {
		my $self = shift;
		my %args = @_;
		return $self->_build_message(
			type	=> 'CopyData',
			data	=> pack('a*', $args{data})
		);
	},
	CopyDone => sub {
		my $self = shift;
		return $self->_build_message(
			type	=> 'CopyDone',
			data	=> '',
		);
	},
# Execute either a named or anonymous portal (prepared statement with bind vars)
	Execute => sub {
		my $self = shift;
		my %args = @_;

		my $msg = pack('Z*N1', defined($args{portal}) ? $args{portal} : '', $args{limit} || 0);
		return $self->_build_message(
			type	=> 'Execute',
			data	=> $msg,
		);
	},
# Parse SQL for a prepared statement
	Parse => sub {
		my $self = shift;
		my %args = @_;
		die "No SQL provided" unless defined $args{sql};

		my $msg = pack('Z*Z*n1', defined($args{statement}) ? $args{statement} : '', $args{sql}, 0);
		return $self->_build_message(
			type	=> 'Parse',
			data	=> $msg,
		);
	},
# Password data, possibly encrypted depending on what the server specified
	PasswordMessage => sub {
		my $self = shift;
		my %args = @_;

		my $pass = $args{password};
		if($self->{password_type} eq 'md5') {
			# md5hex of password . username,
			# then md5hex result with salt appended
			# then stick 'md5' at the front.
			$pass = 'md5' . Digest::MD5::md5_hex(
				Digest::MD5::md5_hex($pass . $self->{user})
				. $self->{password_salt}
			);
		}

		# Yes, protocol requires zero-terminated string format even
		# if we have a binary password value.
		return $self->_build_message(
			type	=> 'PasswordMessage',
			data	=> pack('Z*', $pass)
		);
	},
# Simple query
	Query => sub {
		my $self = shift;
		my %args = @_;
		return $self->_build_message(
			type	=> 'Query',
			data	=> pack('Z*', $args{sql})
		);
	},
# Initial mesage informing the server which database and user we want
	StartupMessage	=> sub {
		my $self = shift;
		die "Not first message" unless $self->is_first_message;

		my %args = @_;
		my $parameters = join('', map { pack('Z*', $_) } map { $_, $args{$_} } grep { exists $args{$_} } qw(user database options));
		$parameters .= "\0";

		return $self->_build_message(
			type	=> undef,
			data	=> pack('N*', PROTOCOL_VERSION) . $parameters
		);
	},
# Synchonise after a prepared statement has finished execution.
	Sync => sub {
		my $self = shift;
		return $self->_build_message(
			type	=> 'Sync',
			data	=> '',
		);
	},
);

# Handlers for specification authentication messages from backend.
my %AUTH_HANDLER = (
	AuthenticationOk => sub {
		my ($self, $msg) = @_;
		$self->_event('authenticated');
		$self->_event('request_ready');
	},
	AuthenticationKerberosV5 => sub {
		my ($self, $msg) = @_;
		die "Not yet implemented";
	},
	AuthenticationCleartextPassword => sub {
		my ($self, $msg) = @_;
		$self->{password_type} = 'plain';
		$self->_event('password');
	},
	AuthenticationMD5Password => sub {
		my ($self, $msg) = @_;
		(undef, undef, undef, my $salt) = unpack('C1N1N1a4', $msg);
		$self->{password_type} = 'md5';
		$self->{password_salt} = $salt;
		$self->_event('password');
	},
	AuthenticationSCMCredential => sub {
		my ($self, $msg) = @_;
		die "Not yet implemented";
	},
	AuthenticationGSS => sub {
		my ($self, $msg) = @_;
		die "Not yet implemented";
	},
	AuthenticationSSPI => sub {
		my ($self, $msg) = @_;
		die "Not yet implemented";
	},
	AuthenticationGSSContinue => sub {
		my ($self, $msg) = @_;
		die "Not yet implemented";
	}
);

# Defined message handlers for incoming messages from backend
our %BACKEND_MESSAGE_HANDLER = (
# We had some form of authentication request or response, pass it over to an auth handler to deal with it further.
	AuthenticationRequest	=> sub {
		my $self = shift;
		my $msg = shift;

		my (undef, undef, $auth_code) = unpack('C1N1N1', $msg);
		my $auth_type = $AUTH_TYPE{$auth_code} or die "Invalid auth code $auth_code received";
		$self->debug("Auth message [$auth_type]");
		return $AUTH_HANDLER{$auth_type}->($self, $msg);
	},
# Key data for cancellation requests
	BackendKeyData	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size, my $pid, my $key) = unpack('C1N1N1N1', $msg);
		$self->_event('backendkeydata',
			pid	=> $pid,
			key	=> $key
		);
	},
# A bind operation has completed
	BindComplete	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		$self->_event('bind_complete');
	},
# We have closed the connection to the server successfully
	CloseComplete	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		$self->_event('close_complete');
	},
# A command has completed, we should see a ready response immediately after this
	CommandComplete => sub {
		my $self = shift;
		my $msg = shift;
		my (undef, undef, $result) = unpack('C1N1Z*', $msg);
		$self->_event('command_complete', result => $result);
	},
# We have a COPY response from the server indicating that it's ready to accept COPY data
	CopyInResponse => sub {
		my $self = shift;
		my $msg = shift;
		(undef, undef, my $type, my $count) = unpack('C1N1C1n1', $msg);
		substr $msg, 0, 8, '';
		my @formats;
		for (1..$count) {
			push @formats, unpack('n1', $msg);
			substr $msg, 0, 2, '';
		}
		$self->_event('copy_in_response', count => $count, columns => \@formats);
	},
# The basic SQL result - a single row of data
	DataRow => sub {
		my $self = shift;
		my $msg = shift;
		my (undef, undef, $count) = unpack('C1N1n1', $msg);
		substr $msg, 0, 7, '';
		my @fields;
		my $desc = $self->row_description;
		foreach my $idx (0..$count-1) {
			my $field = $desc->field_index($idx);
			my ($size) = unpack('N1', $msg);
			substr $msg, 0, 4, '';
			my $data;
			my $null = ($size == 0xFFFFFFFF);
			unless($null) {
				$data = $field->parse_data($msg, $size);
				substr $msg, 0, $size, '';
			}
			push @fields, {
				null		=> $null,
				description	=> $field,
				data		=> $null ? undef : $data,
			}
		}
		$self->_event('data_row', row => \@fields);
	},
# Response given when empty query (whitespace only) is provided
	EmptyQueryResponse => sub {
		my $self = shift;
		my $msg = shift;
		$self->_event('empty_query');
		$self->_event('ready_for_query');
	},
# An error occurred, can indicate that connection is about to close or just be a warning
	ErrorResponse => sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		substr $msg, 0, 5, '';
		my %notice;
		FIELD:
		while(length($msg)) {
			my ($code, $str) = unpack('A1Z*', $msg);
			last FIELD unless $code && $code ne "\0";

			die "Unknown NOTICE code [$code]" unless exists $NOTICE_CODE{$code};
			$notice{$NOTICE_CODE{$code}} = $str;
			substr $msg, 0, 2+length($str), '';
		}
		$self->_event('error', error => \%notice);
	},
# Result from calling a function
	FunctionCallResponse	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size, my $len) = unpack('C1N1N1', $msg);
		substr $msg, 0, 9, '';
		my $data = ($len == 0xFFFFFFFF) ? undef : substr $msg, 0, $len;
		$self->_event('function_call_response', data => $data);
	},
# No data follows
	NoData	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		$self->_event('no_data');
	},
# We have a notice, which is like an error but can be just informational
	NoticeResponse => sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		substr $msg, 0, 5, '';
		my %notice;
		FIELD:
		while(length($msg)) {
			my ($code, $str) = unpack('A1Z*', $msg);
			last FIELD unless $code && $code ne "\0";

			die "Unknown NOTICE code [$code]" unless exists $NOTICE_CODE{$code};
			$notice{$NOTICE_CODE{$code}} = $str;
			substr $msg, 0, 2+length($str), '';
		}
		$self->_event('notice', notice => \%notice);
	},
# LISTEN/NOTIFY mechanism
	NotificationReponse => sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size, my $pid, my $channel, my $data) = unpack('C1N1N1Z*Z*', $msg);
		$self->_event('notification', pid => $pid, channel => $channel, data => $data);
	},
# Connection parameter information
	ParameterStatus	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		substr $msg, 0, 5, '';
		my %status;
		# Series of key,value pairs
		PARAMETER:
		while(1) {
			my ($k, $v) = unpack('Z*Z*', $msg);
			last PARAMETER unless defined($k) && length($k);
			$status{$k} = $v;
			substr $msg, 0, length($k) + length($v) + 2, '';
		}
		$self->_event('parameter_status', status => \%status);
	},
# Description of the format that subsequent parameters are using, typically plaintext only
	ParameterDescription => sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size, my $count) = unpack('C1N1n1', $msg);
		substr $msg, 0, 7, '';
		my @oid_list;
		for my $idx (1..$count) {
			my ($oid) = unpack('N1', $msg);
			substr $msg, 0, 4, '';
			push @oid_list, $oid;
		}
		$self->_event('parameter_description', parameters => \@oid_list);
	},
# Parse request succeeded
	ParseComplete	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		$self->_event('parse_complete');
	},
# Portal has sent enough data to meet the row limit, should be requested again if more is required
	PortalSuspended	=> sub {
		my $self = shift;
		my $msg = shift;
		(undef, my $size) = unpack('C1N1', $msg);
		$self->_event('portal_suspended');
	},
# All ready to accept queries
	ReadyForQuery	=> sub {
		my $self = shift;
		my $msg = shift;
		my (undef, undef, $state) = unpack('C1N1A1', $msg);
		$self->debug("Backend state is $state");
		$self->backend_state($BACKEND_STATE{$state});
		$self->_event('ready_for_query');
	},
# Information on the row data that's expected to follow
	RowDescription => sub {
		my $self = shift;
		my $msg = shift;
		my (undef, undef, $count) = unpack('C1N1n1', $msg);
		my $row = Protocol::PostgreSQL::RowDescription->new;
		substr $msg, 0, 7, '';
		foreach my $id (0..$count-1) {
			my ($name, $table_id, $field_id, $data_type, $data_size, $type_modifier, $format_code) = unpack('Z*N1n1N1n1N1n1', $msg);
			my %data = (
				name		=> $name,
				table_id	=> $table_id,
				field_id	=> $field_id,
				data_type	=> $data_type,
				data_size	=> $data_size,
				type_modifier	=> $type_modifier,
				format_code	=> $format_code
			);
			$self->debug($_ . ' => ' . $data{$_}) for sort keys %data;
			my $field = Protocol::PostgreSQL::FieldDescription->new(%data);
			$row->add_field($field);
			substr $msg, 0, 19 + length($name), '';
		}
		$self->row_description($row);
		$self->_event('row_description', description => $row);
	},
);

=head1 METHODS

=cut

=head2 new

Instantiate a new object.

=cut

sub new {
	my $self = bless {
	}, shift;
	$self->init(@_);
}

sub init {
	my $self = shift;
	my %args = @_;
	$self->{authenticated} = 0;
	$self->{message_count} = 0;
	$self->{debug} = 1 if delete $args{debug};
	$self->{_callback}->{$_} = $args{$_} for grep /^on_/, keys %args;
	return $self;
}

=head2 is_authenticated

Returns true if we are authenticated (and can start sending real data).

=cut

sub is_authenticated { shift->{authenticated} ? 1 : 0 }

=head2 is_first_message

Returns true if this is the first message, as per L<http://developer.postgresql.org/pgdocs/postgres/protocol-overview.html>:

 "For historical reasons, the very first message sent by the client (the startup message) has no initial message-type byte."

=cut

sub is_first_message { shift->{message_count} < 1 }

=head2 initial_request

=cut

sub initial_request {
	my $self = shift;
	my %args = @_;
	my %param = map { $_ => exists $args{$_} ? delete $args{$_} : $self->{$_} } qw(database user);
	delete @param{grep { !defined($param{$_}) } keys %param};
	die "don't know how to handle " . join(',', keys %args) if keys %args;

	$self->send_message('StartupMessage', %param);
	return $self;
}

=head2 send_message

=cut

sub send_message {
	my $self = shift;
	$self->_event('send_request', $self->message(@_));
	return $self;
}

=head2 message

Creates a new message of the given type.

=cut

sub message {
	my $self = shift;
	my $type = shift;
	die "Message $type unknown" unless exists $FRONTEND_MESSAGE_BUILDER{$type};
	my $msg = $FRONTEND_MESSAGE_BUILDER{$type}->($self, @_);
	$self->debug("send data: [" . join(" ", map sprintf("%02x", ord($_)), split //, $msg) . "]");
	++$self->{message_count};
	return $msg;
}

=head2 attach_event

Attach new handler(s) to the given event(s).

=cut

sub attach_event {
	my $self = shift;
	my %args = @_;
	$self->{_callback}->{"on_$_"} = $args{$_} for keys %args;
	return $self;
}

=head2 debug

Helper method to report debug information.

=cut

sub debug {
	my $self = shift;
	return $self unless $self->{debug};
	if(!ref $self->{debug}) {
		my $now = Time::HiRes::time;
		warn strftime("%Y-%m-%d %H:%M:%S", gmtime($now)) . sprintf(".%03d", int($now * 1000.0) % 1000.0) . " @_\n";
		return $self;
	}
	if(ref $self->{debug} eq 'CODE') {
		$self->{debug}->(@_);
		return $self;
	}
	die "Unknown debug setting " . $self->{debug};
}

=head2 handle_message

=cut

sub handle_message {
	my $self = shift;
	my $msg = shift;
	$self->debug("recv data: [" . join(" ", map sprintf("%02x", ord($_)), split //, $msg) . "]");
	my $code = substr $msg, 0, 1;
	my $type = $BACKEND_MESSAGE_CODE{$code};
	$self->debug("Handle [$type] message");
	die "No handler for $type" unless exists $BACKEND_MESSAGE_HANDLER{$type};
	return $BACKEND_MESSAGE_HANDLER{$type}->($self, $msg);
}

=head2 message_length

Returns the length of the given message.

=cut

sub message_length {
	my $self = shift;
	my $msg = shift;
	return undef unless length($msg) >= 5;
	my ($code, $len) = unpack('C1N1', substr($msg, 0, 5));
	return $len;
}

=head2 simple_query

Send a simple query to the server - only supports plain queries (no bind parameters).

=cut

sub simple_query {
	my $self = shift;
	my $sql = shift;
	die "Invalid backend state" if $self->backend_state eq 'error';
	$self->debug("Running query [$sql]");
	$self->send_message('Query', sql => $sql);
	return $self;
}

=head2 copy_data

Send copy data to the server.

=cut

sub copy_data {
	my $self = shift;
	my $data = shift;
	die "Invalid backend state" if $self->backend_state eq 'error';
	$self->send_message('CopyData', data => $data);
	return $self;
}

=head2 copy_done

Indicate that the COPY data from the client is complete.

=cut

sub copy_done {
	my $self = shift;
	my $data = shift;
	die "Invalid backend state" if $self->backend_state eq 'error';
	$self->send_message('CopyDone');
	return $self;
}

=head2 backend_state

Accessor for current backend state.

=cut

sub backend_state {
	my $self = shift;
	if(@_) {
		my $state = shift;
		die "bad state code" unless grep { $state eq $_ } qw(idle transaction error);
		$self->{backend_state} = $state;
		return $self;
	}
	return $self->{backend_state};
}

=head2 row_description

Accessor for row description.

=cut

sub row_description {
	my $self = shift;
	if(@_) {
		$self->{row_description} = shift;
		return $self;
	}
	return $self->{row_description};
}

sub prepare {
	my $self = shift;
	my $sql = shift;
	return $self->prepare_async(sql => $sql);
}

sub prepare_async {
	my $self = shift;
	my %args = @_;
	die "SQL statement not provided" unless defined $args{sql};

	my $sth = Protocol::PostgreSQL::Statement->new(
		dbh	=> $self,
		sql	=> $args{sql}
	);
	return $sth;
}

sub send_copy_data {
	my $self = shift;
	my $data = shift;
	my @out;
	foreach (@$data) {
		my $v = $_;
		if(defined $v) {
			$v =~ s/\\/\\\\/g;
			$v =~ s/\x08/\\b/g;
			$v =~ s/\f/\\f/g;
			$v =~ s/\n/\\n/g;
			$v =~ s/\t/\\t/g;
			$v =~ s/\v/\\v/g;
		} else {
			$v = '\N';
		}
		push @out, $v;
	}
	$self->copy_data(join("\t", @out) . "\n");
}

=head2 _event

Calls the given event callback if we have one.

=cut

sub _event {
	my $self = shift;
	my $type = shift;
	$type = "on_$type";
	my $code = $self->{_callback}->{$type} || $self->can($type);
#	$self->debug("Had $type with $code");
	$code->($self, @_) if $code;
	return $self;
}

=head2 _build_message

Construct a new message.

=cut

sub _build_message {
	my $self = shift;
	my %args = @_;

# Can be undef
	die "No type provided" unless exists $args{type};
	die "No data provided" unless exists $args{data};

# Length includes the 4-byte length field, but not the type byte
	my $length = length($args{data}) + 4;
	return ($self->is_first_message ? '' : $MESSAGE_TYPE_FRONTEND{$args{type}}) . pack('N1', $length) . $args{data};
}

1;

__END__

=head1 SEE ALSO

L<DBD::Pg>, which uses the official library and (unlike this module) provides full support for L<DBI>.

=head1 AUTHOR

Tom Molesworth <cpan@entitymodel.com>

=head1 LICENSE

Copyright Tom Molesworth 2010-2011. Licensed under the same terms as Perl itself.