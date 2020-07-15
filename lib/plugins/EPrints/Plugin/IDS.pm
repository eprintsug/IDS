######################################################################
#
# IDS - intrusion detection system plugin
# 
# 	aim:	save us from intrusion detection via cgi parameters
#	usage:	EPrints::Plugin::IDS::check_ids();
# 	works:	logs and exits if IDS is presumed.
# 	more:	see also https://metacpan.org/pod/CGI::IDS
# 	
# 	2020/07/15/jw
#
# Jens Witzel
# Zentrale Informatik
# Universität Zürich
# Stampfenbachstr. 73
# CH-8006 Zürich
#
###############################################################################


=head1 NAME

EPrints::Plugin::IDS - Plug-in to save us from intrusion detection via cgi

=head1 DESCRIPTION

=item check_ids()

checks weather there are conspicuous strings / commands in parameters

=back

=cut

package EPrints::Plugin::IDS;

use strict;
use warnings;
use utf8;

use lib '_PATH_TO_CPAN_LIB_';
use CGI;
use CGI::IDS;
use Data::Dumper;

use base 'EPrints::Plugin';

sub new
{
	my( $class, %params ) = @_;

	my $self = $class->SUPER::new( %params );

	$self->{name} = "IDS";
	$self->{visible} = "all";

	return $self;
}

sub check_ids
{
	my $conf = $EPrints::SystemSettings::conf;
	my $cgi = new CGI;
	my $ids = new CGI::IDS(
    		whitelist_file  => '_PATH_TO_ARCHIVE_/cfg/cfg.d/YOUR_whitelist.xml',
    		disable_filters => [58,59,60],
	);
	my $query = new CGI;

	# start detection
	my %params = $cgi->Vars;
	my $impact = $ids->detect_attacks( request => \%params );
	my $error = $ids->get_attacks( request => \%params );
	
	# analyze impact, log but do not inform the attacker
	if ($impact > 0) {
		my $filename_dumper = $conf->{base_path} . '/var/ids.log';
		open(my $fh_dumper, '>>', $filename_dumper) or die "Could not open file '$filename_dumper' !";
		say $fh_dumper "*** Intrusion Detection (IDS) via $0";
		say $fh_dumper "IP: ".$ENV{REMOTE_ADDR};
		say $fh_dumper "DATE: ". localtime();
        	if ($query->param()) {
        		my $attacks = $ids->get_attacks();
            		foreach my $attack (@$attacks) {
               			say $fh_dumper "FILTERS MATCHED: ".   join("\n", map {"#$_: " . $ids->get_rule_description(rule_id => $_)} @{$attack->{matched_filters}});
               			say $fh_dumper "TAGS MATCHED: ".   join(",", @{$attack->{matched_tags}});
               			say $fh_dumper "VALUE: ". $query->pre($query->escapeHTML($attack->{value_converted}));
            		}
        	}
		say $fh_dumper "\n";
		close $fh_dumper;
		exit;
	}
	return;
}

1;
