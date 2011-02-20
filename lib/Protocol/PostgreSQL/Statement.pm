package Protocol::PostgreSQL::Statement;
BEGIN {
  $Protocol::PostgreSQL::Statement::VERSION = '0.005';
}
use strict;
use warnings;

=head1 NAME

Protocol::PostgreSQL::Statement - prepared statement handling

=head1 VERSION

version 0.005

=head1 SYNOPSIS

 my $sth = Protocol::PostgreSQL::Statement->new(dbh => $dbh, sql => 'select * from table where id = ?');
 $sth->bind(123);
 $sth->execute;

=head1 DESCRIPTION

Provides prepared-statement support for L<Protocol::PostgreSQL>.

=cut

=head1 METHODS

=cut

=head2 C<new>

Instantiate a new object, takes two named parameters:

=over 4

=item * dbh - L<Protocol::PostgreSQL>-compatible object for the parent database handle

=item * sql - actual SQL query to run, with placeholders specified as ?

=back

Will send the parse request immediately.

=cut

sub new {
	my $class = shift;
	my %args = @_;
	die "No DBH?" unless $args{dbh};
	die "No SQL?" unless defined $args{sql};

	my $self = bless {
		dbh	        => $args{dbh},
		sql	        => $args{sql},
                  (exists $args{statement})
                ? (statement    => $args{statement})
                : (),
	}, $class;
	$self->dbh->send_message(
		'Parse',
		sql => $args{sql},
		  (exists $args{statement})
		? (statement    => $args{statement})
		: ()
	);
	return $self;
}

=head2 C<bind>

Bind variables to the current statement.

=cut

sub bind {
	my $self = shift;
	$self->dbh->send_message(
		'Bind',
		param => [ @_ ],
		  (exists $self->{statement})
		? (statement	=> $self->{statement})
		: ()
	);
}

=head2 C<execute>

Execute this query.

=cut

sub execute {
	my $self = shift;
	$self->dbh->row_description($self->row_description);
	$self->dbh->send_message(
		'Execute',
		param => [ @_ ],
		sth => $self,
#		  (exists $self->{statement})
#		? (portal => $self->{statement})
#		: ()
	);
}

=head2 C<describe>

Describe this query.

=cut

sub describe {
	my $self = shift;
	$self->dbh->active_statement($self);
	$self->dbh->send_message(
		'Describe',
		param => [ @_ ],
		  (exists $self->{statement})
		? (statement => $self->{statement})
		: (),
		sth => $self,
	);
}

use Data::Dumper;
sub row_description {
	my $self = shift;
	if(@_) {
		$self->{row_description} = shift;
		return $self;
	}
	return $self->{row_description};
}

=head1 C<finish>

Finish the current statement. Issues a Sync which should trigger a ReadyForQuery response.

=cut

sub finish {
	my $self = shift;
	$self->dbh->send_message('Sync');
}

=head2 C<dbh>

Accessor for the database handle (L<Protocol::PostgreSQL> object).

=cut

sub dbh { shift->{dbh} }

1;

__END__

=head1 AUTHOR

Tom Molesworth <cpan@entitymodel.com>

=head1 LICENSE

Copyright Tom Molesworth 2010-2011. Licensed under the same terms as Perl itself.