#!/usr/bin/perl -w
#
# $Id: mrtg-rrd.cgi,v 1.35 2003/08/18 15:58:57 kas Exp $
#
# mrtg-rrd.cgi: The script for generating graphs for MRTG statistics.
#
# Loosely modelled after the Rainer.Bawidamann@informatik.uni-ulm.de's
# 14all.cgi
#
#   Copyright (C) 2001 Jan "Yenya" Kasprzak <kas@fi.muni.cz>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

use strict;

use POSIX qw(strftime);
use Time::Local;

# The %.1f should work on 5.005+. There may be other problems, though.
# I've tested this on 5.8.0 only, so mind the gap!
require 5.005;

# Location of RRDs.pm, if it is not in @INC
# use lib '/usr/lib/perl5/5.00503/i386-linux';
use RRDs;

use vars qw(@config_files @all_config_files %targets $config_time
	%directories $version $imagetype);

# EDIT THIS to reflect all your MRTG config files
BEGIN { @config_files = qw(); }

$version = '0.7';

# This depends on what image format your libgd (and rrdtool) uses
$imagetype = 'png'; # or make this 'gif';

# strftime(3) compatibility test
my $percent_h = '%-H';
$percent_h = '%H' if (strftime('%-H', gmtime(0)) !~ /^\d+$/);

sub handler ($)
{
	my ($q) = @_;

	try_read_config($q->url());

	my $path = $q->path_info();
	$path =~ s/^\///;
	$path =~ s/\/$//;
	if (defined $directories{$path}) {
		if ($q->path_info() =~ /\/$/) {
			print_dir($path);
		} else {
			print_error("Unknown monitor: '$path' (original: '" . $q->path_info() . "')");
			#print "Location: ", $q->url(-path_info=>1), "/\n\n";
		}
		return;
	}

	my ($dir, $stat, $ext) = ($q->path_info() =~
		/^(.*)\/([^\/]+)(\.html|-(day|week|month|year)\.$imagetype)$/);

	$dir =~ s/^\///;

    print_error("Undefined statistics: '$stat' not found in targets. Available targets: " . join(", ", sort keys %targets))
	    unless defined $targets{$stat};

	print_error("Incorrect directory")
		unless defined $targets{$stat}{directory} || $targets{$stat}{directory} eq $dir;

	my $tgt = $targets{$stat};

	common_args($stat, $tgt, $q);

	# We may be running under mod_perl or something. Do not destroy
	# the original settings of timezone.
	my $oldtz; 
	if (defined $tgt->{timezone}) {
		$oldtz = $ENV{TZ};
		$ENV{TZ} = $tgt->{timezone};
	}

	if ($ext eq '.html') {
		do_html($tgt);
	} elsif ($ext eq '-day.' . $imagetype) {
		do_image($tgt, 'day');
	} elsif ($ext eq '-week.' . $imagetype) {
		do_image($tgt, 'week');
	} elsif ($ext eq '-month.' . $imagetype) {
		do_image($tgt, 'month');
	} elsif ($ext eq '-year.' . $imagetype) {
		do_image($tgt, 'year');
	} else {
		print_error("Unknown extension");
	}
	$ENV{TZ} = $oldtz
		if defined $oldtz;
}

sub do_html($)
{
	my ($tgt) = @_;

	my @day   = do_image($tgt, 'day');
	my @week  = do_image($tgt, 'week');
	my @month = do_image($tgt, 'month');
	my @year  = do_image($tgt, 'year');

	http_headers('text/html', $tgt->{config});
	print <<'EOF';
<HTML>
<HEAD>
<TITLE>
EOF
	print $tgt->{title} if defined $tgt->{title};
	print "</TITLE>\n";

	html_comments($tgt, 'd', @{$day[0]}) if $#day != -1;
	html_comments($tgt, 'w', @{$week[0]}) if $#week != -1;
	html_comments($tgt, 'm', @{$month[0]}) if $#month != -1;
	html_comments($tgt, 'y', @{$year[0]}) if $#year != -1;

	print $tgt->{addhead} if defined $tgt->{addhead};

	print "</HEAD>\n", $tgt->{bodytag}, "\n";
	
	print $tgt->{pagetop} if defined $tgt->{pagetop};

	print "<p style='font-size:14px;'><a href='../index.html' "
		. "style='color:#5a7ab8;text-decoration:none;'>&larr; Back to monitoring index</a></p>\n";

	unless (defined $tgt->{options}{noinfo}) {
		my @st = stat $tgt->{rrd};

		print "<HR>\nThe statistics were last updated ",
			strftime("<B>%A, %d %B, %H:%M:%S %Z</B>\n",
				localtime($st[9]));
	}

	my $dayavg = $tgt->{config}->{interval};

	html_graph($tgt, 'day', 'Daily', $dayavg . ' Minute', \@day);
	html_graph($tgt, 'week', 'Weekly', '30 Minute', \@week);
	html_graph($tgt, 'month', 'Monthly', '2 Hour', \@month);
	html_graph($tgt, 'year', 'Yearly', '1 Day', \@year);

	unless (defined $tgt->{options}{nolegend}) {
		print <<EOF;
<HR>
<table WIDTH=500 BORDER=0 CELLPADDING=4 CELLSPACING=0>
EOF
		print <<EOF unless ($tgt->{options}{noi});
    <tr>
	<td ALIGN=RIGHT><font SIZE=-1 COLOR="$tgt->{col1}">
		<b>$tgt->{colname1} ###</b></font></td>
	<td><font SIZE=-1>$tgt->{legend1}</font></td>
    </tr>
EOF
		print <<EOF unless ($tgt->{options}{noo});
    <tr>
	<td ALIGN=RIGHT><font SIZE=-1 COLOR="$tgt->{col2}">
		<b>$tgt->{colname2} ###</b></font></td>
	<td><font SIZE=-1>$tgt->{legend2}</font></td>
    </tr>
EOF
		if ($tgt->{withpeak} ne '') {
			print <<EOF unless ($tgt->{options}{noi});
    <tr>
	<td ALIGN=RIGHT><font SIZE=-1 COLOR="$tgt->{col3}">
		<b>$tgt->{colname3} ###</b></font></td>
	<td><font SIZE=-1>$tgt->{legend3}</font></td>
    </tr>
EOF
			print <<EOF unless ($tgt->{options}{noo});
    <tr>
	<td ALIGN=RIGHT><font SIZE=-1 COLOR="$tgt->{col4}">
		<b>$tgt->{colname4} ###</b></font></td>
	<td><font SIZE=-1>$tgt->{legend4}</font></td>
    </tr>
EOF
		}
		print <<EOF;
    </table>
EOF
	}

	print_banner($tgt->{config})
		unless defined $tgt->{options}{nobanner};

	print $tgt->{pagefoot} if defined $tgt->{pagefoot};
	print "\n", <<'EOF';
</body>
</html>
EOF

}

sub html_comments($$@)
{
	my ($tgt, $letter, @val) = @_;

	return if $#val == -1;

	unless ($tgt->{options}{noi}) {
		print "<!-- maxin $letter ", $val[1], " -->\n";
		print "<!-- avin $letter ", $val[3], " -->\n";
		print "<!-- cuin $letter ", $val[5], " -->\n";
	}
	unless ($tgt->{options}{noo}) {
		print "<!-- maxout $letter ", $val[0], " -->\n";
		print "<!-- avout $letter ", $val[2], " -->\n";
		print "<!-- cuout $letter ", $val[4], " -->\n";
	}
}


sub html_graph($$$$$)
{
	my ($tgt, $ext, $freq, $period, $params) = @_;

	return unless defined $tgt->{$ext};

	my @values = @{$params->[0]};
	my $x = $params->[1];
	my $y = $params->[2];

	$x *= $tgt->{xzoom} if defined $tgt->{xzoom};
	$y *= $tgt->{yzoom} if defined $tgt->{yzoom};

	my $kilo = $tgt->{kilo};
	my @kmg = split(',', $tgt->{kmg});

	my $fmt;
	if (defined $tgt->{options}{integer}) {
		$fmt = '%d';
	} else {
		$fmt = '%.1f';
	}

	my @percent = do_percent($tgt, \@values);
	my @relpercent = do_relpercent($tgt, \@values);

	my @nv;
	for my $val (@values) {
		if (@kmg == 0) { # kMG[target]: <empty>
			push @nv, sprintf($fmt, $val);
			next;
		}
		for my $si (@kmg) {
			if ($val < 10000) {
				push @nv, sprintf($fmt, $val) . " $si";
				last;
			}
			$val /= $kilo;
		}
	}
	@values = @nv;

	print "<HR>\n<B>\`$freq\' Graph ($period Average)</B><BR>\n";

	print '<IMG SRC="', $tgt->{url}, '-', $ext, '.' . $imagetype .
		'" WIDTH=', $x, ' HEIGHT=', $y, ' ALT="', $freq,
		' Graph" VSPACE=10 ALIGN=TOP><BR>', "\n";
	print '<TABLE CELLPADDING=0 CELLSPACING=0>';
	print <<EOF if $tgt->{legendi} ne '' && !$tgt->{options}{noi};
    <TR>
	<TD ALIGN=RIGHT><SMALL>Max <FONT COLOR="$tgt->{col1}">$tgt->{legendi}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$values[1]$tgt->{shortlegend}$percent[1]</SMALL></TD>
	<TD WIDTH=5></TD>
	<TD ALIGN=RIGHT><SMALL>Average <FONT COLOR="$tgt->{col1}">$tgt->{legendi}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$values[3]$tgt->{shortlegend}$percent[3]</SMALL></TD>
	<TD WIDTH=5></TD>
	<TD ALIGN=RIGHT><SMALL>Current <FONT COLOR="$tgt->{col1}">$tgt->{legendi}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$values[5]$tgt->{shortlegend}$percent[5]</SMALL></TD>
    </TR>
EOF
	print <<EOF if $tgt->{legendo} ne '' && !$tgt->{options}{noo};
    <TR>
	<TD ALIGN=RIGHT><SMALL>Max <FONT COLOR="$tgt->{col2}">$tgt->{legendo}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$values[0]$tgt->{shortlegend}$percent[0]</SMALL></TD>
	<TD WIDTH=5></TD>
	<TD ALIGN=RIGHT><SMALL>Average <FONT COLOR="$tgt->{col2}">$tgt->{legendo}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$values[2]$tgt->{shortlegend}$percent[2]</SMALL></TD>
	<TD WIDTH=5></TD>
	<TD ALIGN=RIGHT><SMALL>Current <FONT COLOR="$tgt->{col2}">$tgt->{legendo}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$values[4]$tgt->{shortlegend}$percent[4]</SMALL></TD>
EOF
	if (defined $tgt->{options}{dorelpercent}) {
		print <<"EOF";
    </TR><TR>
	<TD ALIGN=RIGHT><SMALL>Max <FONT COLOR="$tgt->{col5}">&nbsp;Percentage:</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$relpercent[0]</SMALL></TD>
	<TD WIDTH=5></TD>
	<TD ALIGN=RIGHT><SMALL>Average <FONT COLOR="$tgt->{col5}">&nbsp;Percentage:</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$relpercent[1]</SMALL></TD>
	<TD WIDTH=5></TD>
	<TD ALIGN=RIGHT><SMALL>Current <FONT COLOR="$tgt->{col5}">&nbsp;Percentage:</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$relpercent[2]</SMALL></TD>
EOF
	}

	# Percentile row - displayed when Percentile[target] is configured
	# params->[3] contains [pct_in, pct_out] from do_image() VDEF/PRINT values
	if (defined $tgt->{percentile} && defined $params->[3]) {
		my ($pct_in, $pct_out) = @{$params->[3]};
		my $pct_label = "$tgt->{percentile}th Percentile";
		$pct_in  = defined $pct_in  ? sprintf('%.1f', $pct_in)  : 'N/A';
		$pct_out = defined $pct_out ? sprintf('%.1f', $pct_out) : 'N/A';
		print <<EOF unless ($tgt->{options}{noi} && $tgt->{options}{noo});
    </TR><TR>
EOF
		print <<EOF unless ($tgt->{options}{noi});
	<TD ALIGN=RIGHT><SMALL>$pct_label <FONT COLOR="$tgt->{col1}">$tgt->{legendi}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$pct_in$tgt->{shortlegend}</SMALL></TD>
	<TD WIDTH=5></TD>
EOF
		print <<EOF unless ($tgt->{options}{noo});
	<TD ALIGN=RIGHT><SMALL>$pct_label <FONT COLOR="$tgt->{col2}">$tgt->{legendo}</FONT></SMALL></TD>
	<TD ALIGN=RIGHT><SMALL>&nbsp;$pct_out$tgt->{shortlegend}</SMALL></TD>
	<TD WIDTH=5></TD><TD></TD>
EOF
	}

	print <<'EOF';
    </TR>
</TABLE>
EOF
}

sub do_percent($$)
{
	my ($tgt, $values) = @_;

	my @percent = ('', '', '', '', '', '');

	return @percent if defined $tgt->{options}{nopercent};

	for my $val (0..$#$values) {
		my $mx = ($val % 2 == 1) ? $tgt->{maxbytes1} : $tgt->{maxbytes2};
		next unless defined $mx;
		my $p = sprintf("%.1f", $values->[$val]*100/$mx);
		$percent[$val] = ' (' . $p . '%)';
	}

	@percent;
}

sub do_relpercent($$)
{
	my ($tgt, $values) = @_;

	my @percent = ('', '', '');

	return @percent unless defined $tgt->{options}{dorelpercent};

	for my $val (0..2) {
		$percent[$val] = sprintf("%.1f",
			$values->[2*$val+1] * 100 / $values->[2*$val])
			if $values->[2*$val] > 0;
		$percent[$val] ||= 0;
		$percent[$val] .= ' %';
	}

	@percent;
}

sub http_headers($$)
{
	my ($content_type, $cfg) = @_;

	print <<"EOF";
Content-Type: $content_type
Refresh: $cfg->{refresh}
Pragma: no-cache
EOF
	# Expires header calculation stolen from CGI.pm
	print strftime("Expires: %a, %d %b %Y %H:%M:%S GMT\n",
		gmtime(time+60*$cfg->{interval}));

	print "\n";
}

sub do_image($$)
{
	my ($target, $ext) = @_;

	my $file = $target->{$ext};

	return unless defined $file;

	# Now the vertical rule at the end of the day
	my @t = localtime(time);
	$t[0] = $t[1] = $t[2] = 0;

	my $seconds;
	my $oldsec;
	my $back;
	my $xgrid;

	my $unscaled;
	my $withpeak;

	my $noi = 1 if $target->{options}{noi};
	my $noo = 1 if $target->{options}{noo};

	if ($ext eq 'day') {
		$seconds = timelocal(@t);
		$back = 30*3600;	# 30 hours
		$oldsec = $seconds - 86400;
		$unscaled = 1 if $target->{unscaled} =~ /d/;
		$withpeak = 1 if $target->{withpeak} =~ /d/;
		# We need this only for day graph. The other ones
		# are magically correct.
		$xgrid = 'HOUR:1:HOUR:6:HOUR:2:0:' . $percent_h;
	} elsif ($ext eq 'week') {
		$seconds = timelocal(@t);
		$t[6] = ($t[6]+6) % 7;
		$seconds -= $t[6]*86400;
		$back = 8*86400;	# 8 days
		$oldsec = $seconds - 7*86400;
		$unscaled = 1 if $target->{unscaled} =~ /w/;
		$withpeak = 1 if $target->{withpeak} =~ /w/;
	} elsif ($ext eq 'month') {
		$t[3] = 1;
		$seconds = timelocal(@t);
		$back = 36*86400;	# 36 days
		$oldsec = $seconds - 30*86400; # FIXME (the right # of days!!)
		$unscaled = 1 if $target->{unscaled} =~ /m/;
		$withpeak = 1 if $target->{withpeak} =~ /m/;
	} elsif ($ext eq 'year') {
		$t[3] = 1;
		$t[4] = 0;
		$seconds = timelocal(@t);
		$back = 396*86400;	# 365 + 31 days
		$oldsec = $seconds - 365*86400; # FIXME (the right # of days!!)
		$unscaled = 1 if $target->{unscaled} =~ /y/;
		$withpeak = 1 if $target->{withpeak} =~ /y/;
	} else {
		print_error("Unknown file extension: $ext");
	}

	my @local_args;

	if ($unscaled) {
		@local_args = ('-u', $target->{maxbytes1});
		push @local_args, '--rigid' unless defined $target->{absmax};
	}

	if ($xgrid) {
		push @local_args, '-x', $xgrid;
	}

	my @local_args_end;

	if ($withpeak) {
		push @local_args_end, 'LINE1:maxin'.$target->{col3}.':MaxIn'
			unless $noi;
		push @local_args_end, 'LINE1:maxout'.$target->{col4}.':MaxOut'
			unless $noo;
	}

	if (defined $target->{options}{dualaxis}) {
		my $left_max  = $target->{maxbytes1} || 100000;
		my $right_max = $target->{maxbytes2} || 100;
		my $scale = $right_max / $left_max;
		push @local_args, '--right-axis', "$scale:0";
		push @local_args, '--right-axis-label', $target->{y2legend}
			if defined $target->{y2legend} && $target->{y2legend} ne '';
	}

	# Percentile: add VDEF/PRINT args so RRDs::graph returns the Nth percentile
	# values alongside the standard MAX/AVERAGE/LAST PRINTs. These are appended
	# after all other graph elements so they don't affect the graph visually.
	my @percentile_args;
	if (defined $target->{percentile}) {
		my $n = $target->{percentile};
		push @percentile_args, "VDEF:pctIn=in,$n,PERCENT"   unless $noi;
		push @percentile_args, "PRINT:pctIn:%.2lf"          unless $noi;
		push @percentile_args, "VDEF:pctOut=out,$n,PERCENT" unless $noo;
		push @percentile_args, "PRINT:pctOut:%.2lf"         unless $noo;
	}

	my @rv = RRDs::graph($file, '-s', "-$back", @local_args,
		@{$target->{args}}, "VRULE:$oldsec#ff0000",
		"VRULE:$seconds#ff0000", @local_args_end, @percentile_args);

	my $rrd_error = RRDs::error;
	print_error("RRDs::graph failed, $rrd_error") if defined $rrd_error;

	# In array context: extract percentile PRINTs from the tail of rv[0].
	# RRDs::graph returns PRINT values in rv[0] interleaved with graph stats.
	# Standard PRINTs: [maxout, maxin, avgout, avgin, curout, curin] = 6 values.
	# Percentile PRINTs follow: [pctIn, pctOut] (when both DS present).
	if (wantarray) {
		my @all_prints = @{$rv[0]};

		# Split standard stats (first 6) from percentile values (remainder)
		my @stats   = @all_prints[0..5];
		my @pct_raw = @all_prints[6..$#all_prints];

		# Parse percentile values - order matches PRINT order above:
		# pctIn first (unless noi), pctOut second (unless noo)
		my ($pct_in, $pct_out);
		if (defined $target->{percentile}) {
			my $idx = 0;
			$pct_in  = $pct_raw[$idx++] unless $noi;
			$pct_out = $pct_raw[$idx]   unless $noo;
		}

		if (defined $target->{factor}) {
			@stats = map { $_ * $target->{factor} } @stats;
			$pct_in  *= $target->{factor} if defined $pct_in;
			$pct_out *= $target->{factor} if defined $pct_out;
		}

		my @pct_vals = defined $target->{percentile} ? [$pct_in, $pct_out] : undef;

		if ($noi) {
			return ([$stats[0], 0, $stats[1], 0, $stats[2], 0],
				$rv[1], $rv[2], @pct_vals);
		} elsif ($noo) {
			return ([0, $stats[0], 0, $stats[1], 0, $stats[2]],
				$rv[1], $rv[2], @pct_vals);
		} else {
			return (\@stats, $rv[1], $rv[2], @pct_vals);
		}
	}

	# Not in array context ==> print out the PNG file.
	open PNG, "<$file" or print_error("Can't open $file: $!");

	binmode PNG;

	http_headers("image/$imagetype", $target->{config});

	my $buf;
        # could be sendfile in Linux ;-)
        while(sysread PNG, $buf, 8192) {
                print $buf;
        }
	close PNG;
}

sub common_args($$$)
{
	my ($name, $target, $q) = @_;

	return @{$target->{args}} if $target->{args} && @{$target->{args}};

	my $noi = 1 if $target->{options}{noi};
	my $noo = 1 if $target->{options}{noo};

	$target->{name} = $name;

	$target->{directory} = ''
		unless defined $target->{directory};

	my $tdir = $target->{directory};
	$tdir .= '/'
		unless $tdir eq '' || $tdir =~ /\/$/;

	$target->{url} = $q->url . '/' . $tdir . $name;

	my $cfg = $target->{config};

	my $dir = $cfg->{workdir};
	$dir = $cfg->{logdir}
		if defined $cfg->{logdir};

    # Check if target is in ds0&ds1:rrdfile format (for external RRD files)
    if (defined $target->{target}) {
        if ($target->{target} =~ /^(.+)&(.+):(.+)$/) {
            my ($ds0_name, $ds1_name, $rrd_file) = ($1, $2, $3);
            $target->{rrd} = $rrd_file if defined $rrd_file && $rrd_file ne '';
            $target->{ds0} = $ds0_name;
            $target->{ds1} = $ds1_name;
        }
    }

    # Set default RRD path if not already set by target parsing
    $target->{rrd} = $dir . '/' . $tdir . $name . '.rrd'
        unless defined $target->{rrd};

    # Set default data source names if not specified
    $target->{ds0} = 'ds0' unless defined $target->{ds0};
    $target->{ds1} = 'ds1' unless defined $target->{ds1};

    %{$target->{options}} = ()
        unless $target->{options};

	$dir = $cfg->{workdir};
	$dir = $cfg->{imagedir}
		if defined $cfg->{imagedir};

	$target->{suppress} ||= '';

	$target->{day}   = $dir . '/' . $tdir . $name
		. '-day.' . $imagetype unless $target->{suppress} =~ /d/;
	$target->{week}  = $dir . '/' . $tdir . $name
		. '-week.' . $imagetype unless $target->{suppress} =~ /w/;
	$target->{month} = $dir . '/' . $tdir . $name
		. '-month.' . $imagetype unless $target->{suppress} =~ /m/;
	$target->{year}  = $dir . '/' . $tdir . $name
		. '-year.' . $imagetype unless $target->{suppress} =~ /y/;

	$target->{maxbytes1} = $target->{maxbytes}
		if defined $target->{maxbytes} && !defined $target->{maxbytes1};

	$target->{maxbytes2} = $target->{maxbytes1}
		if defined $target->{maxbytes1} && !defined $target->{maxbytes2};

	my @args = ();

	push @args, '--lazy', '-c', 'FONT#000000', '-c',
		'MGRID#000000', '-c', 'FRAME#000000',
		'-g', '-l', '0';

	$target->{background} = '#f5f5f5'
		unless defined $target->{background};

	push @args, '-c', 'BACK'. $target->{background};

	push @args, '-c', 'SHADEA' . $target->{background},
		'-c', 'SHADEB' . $target->{background}
		if defined $target->{options}{noborder};

	if (defined $target->{options}{noarrow}) {
		push @args, '-c', 'ARROW' . $target->{background};
	} else {
		push @args, '-c', 'ARROW#000000';
	}

	push @args, '-b', $target->{kilo}
		if defined $target->{kilo};

	if (defined $target->{xsize}) {
		if (defined $target->{xscale}) {
			push @args, '-w', $target->{xsize}*$target->{xscale};
		} else {
			push @args, '-w', $target->{xsize};
		}
	}

	if (defined $target->{ysize}) {
		if (defined $target->{yscale}) {
			push @args, '-h', $target->{ysize}*$target->{yscale};
		} else {
			push @args, '-h', $target->{ysize};
		}
	}

	my $scale = 1;

	if (defined $target->{options}->{perminute}) {
		$scale *= 60;
	} elsif (defined $target->{options}->{perhour}) {
		$scale *= 3600;
	}

	if (defined $target->{options}->{bits}) {
		$scale *= 8;
		$target->{ylegend} = 'Bits per second'
			unless defined $target->{ylegend};
		$target->{legend1} = 'Incoming Traffic in Bits per Second'
			unless defined $target->{legend1};
		$target->{legend2} = 'Outgoing Traffic in Bits per Second'
			unless defined $target->{legend2};
		$target->{legend3} = 'Peak Incoming Traffic in Bits per Second'
			unless defined $target->{legend3};
		$target->{legend4} = 'Peak Outgoing Traffic in Bits per Second'
			unless defined $target->{legend4};
		$target->{shortlegend} = 'b/s'
			unless defined $target->{shortlegend};
	} else {
		$target->{ylegend} = 'Bytes per second'
			unless defined $target->{ylegend};
		$target->{legend1} = 'Incoming Traffic in Bytes per Second'
			unless defined $target->{legend1};
		$target->{legend2} = 'Outgoing Traffic in Bytes per Second'
			unless defined $target->{legend2};
		$target->{legend3} = 'Peak Incoming Traffic in Bytes per Second'
			unless defined $target->{legend3};
		$target->{legend4} = 'Peak Outgoing Traffic in Bytes per Second'
			unless defined $target->{legend4};
		$target->{shortlegend} = 'B/s'
			unless defined $target->{shortlegend};
	}

    if ($scale > 1) {
        push @args, "DEF:in0=$target->{rrd}:$target->{ds0}:AVERAGE",
            "CDEF:in=in0,$scale,*",
            "DEF:maxin0=$target->{rrd}:$target->{ds0}:MAX",
            "CDEF:maxin=maxin0,$scale,*"
            unless $noi;
        push @args, "DEF:out0=$target->{rrd}:$target->{ds1}:AVERAGE",
            "CDEF:out=out0,$scale,*",
            "DEF:maxout0=$target->{rrd}:$target->{ds1}:MAX",
            "CDEF:maxout=maxout0,$scale,*"
            unless $noo;
    } else {
        push @args, "DEF:in=$target->{rrd}:$target->{ds0}:AVERAGE",
            "DEF:maxin=$target->{rrd}:$target->{ds0}:MAX"
            unless $noi;
        push @args, "DEF:out=$target->{rrd}:$target->{ds1}:AVERAGE",
            "DEF:maxout=$target->{rrd}:$target->{ds1}:MAX"
            unless $noo;
    }

	my $i=1;
	for my $coltext (split(/,/, $target->{colours})) {
		my ($text, $rgb) = ($coltext =~ /^([^#]+)(#[0-9a-fA-F]{6})$/);
		$target->{'col'.$i} = $rgb;
		$target->{'colname'.$i} = $text;
		$i++;
	}

	push @args, '-v', $target->{ylegend};

	push @args, 'AREA:in' . $target->{col1} . ':In',
		unless $noi;
	push @args, 'LINE2:out' . $target->{col2} . ':Out'
		unless $noo;

	push @args, 'PRINT:out:MAX:%.1lf' unless $noo;
	push @args, 'PRINT:in:MAX:%.1lf'  unless $noi;
	push @args, 'PRINT:out:AVERAGE:%.1lf' unless $noo;
	push @args, 'PRINT:in:AVERAGE:%.1lf'  unless $noi;
	push @args, 'PRINT:out:LAST:%.1lf' unless $noo;
	push @args, 'PRINT:in:LAST:%.1lf'  unless $noi;

	if (defined $target->{maxbytes1}) {
		$target->{maxbytes1} *= $scale;
		push @args, 'HRULE:' . $target->{maxbytes1} . '#cc0000';
	}

	if (defined $target->{maxbytes2}) {
		$target->{maxbytes2} *= $scale;
		push @args, 'HRULE:' . $target->{maxbytes2} . '#cccc00'
			if $target->{maxbytes2} != $target->{maxbytes1};
	}

	@{$target->{args}} = @args;

	@args;
}

sub try_read_config($)
{
	my ($prefix) = (@_);
	$prefix =~ s/\/[^\/]*$//;

	# Verify the version of RRDtool:
	if (!defined $RRDs::VERSION || $RRDs::VERSION < 1.000331) {
		print_error("Please install more up-to date RRDtool - need at least 1.000331");
	}

	my $read_cfg;
	if (!defined $config_time) {
		$read_cfg = 1;
	} else {
		for my $file (@all_config_files) {
			my @stat = stat $file;
			if ($config_time < $stat[9]) {
				$read_cfg = 1;
				last;
			}
		}
	}

	return unless $read_cfg;

	my %defaults = (
		xsize => 400,
		ysize => 100,
		kmg => ',k,M,G,T,P',
		kilo => 1000,
		bodytag => "<BODY BGCOLOR=#ffffff>\n",
		colours => 'GREEN#00cc00,BLUE#0000ff,DARK GREEN#006600,MAGENTA#ff00ff,AMBER#ef9f4f',
		legendi => '&nbsp;In:',
		legendo => '&nbsp;Out:',
		unscaled => '',
		withpeak => '',
		directory => '',
	);

	%targets = ();

	@all_config_files = @config_files;

	my $order = 0;
	for my $cfgfile (@config_files) {
		%{$targets{_}} = %defaults;
		%{$targets{'^'}} = ();
		%{$targets{'$'}} = ();

		my $cfgref = {
			refresh => 300,
			interval => 5,
			icondir => $prefix
		};

		read_mrtg_config($cfgfile, \%defaults, $cfgref, \$order);
	}

	delete $targets{'^'};
	delete $targets{_};
	delete $targets{'$'};

	parse_directories();

	$config_time = time;
}

sub read_mrtg_config($$$$);

sub read_mrtg_config($$$$)
{
	my ($file, $def, $cfgref, $order) = @_;

	my %defaults = %$def;

	# Skip if file doesn't exist
	unless (-e $file) {
		warn "Warning: Config file '$file' not found, skipping\n" if $^W;
		return;
	}

	my @lines;

	# Use 'or' instead of '||' to avoid calling print_error on failure
	unless (open(CFG, "<$file")) {
		warn "Warning: Cannot open config file '$file': $!, skipping\n" if $^W;
		return;
	}

	while (<CFG>) {
		chomp;                    # remove newline
		s/\s+$//;                 # remove trailing space
		s/\s+/ /g;                # collapse white spaces to ' '
		next if /^ *\#/;           # skip comment lines
		next if /^\s*$/;          # skip empty lines
		if (/^ \S/) {             # multiline options
			$lines[$#lines] .= $_;
		} else {
			push @lines, $_;
		}
	}
	close CFG;

	foreach (@lines) {
		if (/^\s*([\w\d]+)\[(\S+)\]\s*:\s*(.*)$/) {
			my ($tgt, $opt, $val) = ($2, lc($1), $3);
			unless (exists $targets{$tgt}) {
				# pre-set defaults constructed on all of ^, _, and $
				for my $key (%{$targets{'^'}}) {
					$targets{$tgt}{$key} = $targets{'^'}{$key};
				}
				for my $key (%{$targets{'$'}}) {
					$targets{$tgt}{$key} .= $targets{'$'}{$key};
				}
				# WARNING: Tobi explicitly said that when all ^, _, and $
				# options are set, the result should be just the value
				# of the _ option (when the option itself is not explicitly
				# defined. I do not agree with him here but I respect this
				# and will try to be compatible with MRTG.
				for my $key (%{$targets{'_'}}) {
					$targets{$tgt}{$key} = $targets{'_'}{$key};
				}

				# anonymous hash ref - need copy, not ref
				delete $targets{$tgt}{options};
				# The same as above - we need to create this
				# based on [^], [_], and [$] values
				%{$targets{$tgt}{options}} = ();
				%{$targets{$tgt}{options}} = %{$targets{'^'}{options}}
					if defined $targets{'^'}{options};
				%{$targets{$tgt}{options}} = (%{$targets{$tgt}{options}},
					%{$targets{'_'}{options}})
					if defined $targets{'_'}{options};
				%{$targets{$tgt}{options}} = (%{$targets{$tgt}{options}},
					%{$targets{'$'}{options}})
					if defined $targets{'$'}{options};

				$targets{$tgt}{order} = ++$$order;
				$targets{$tgt}{config} = $cfgref;
			}
			if ($tgt eq '_' && $val eq '') {
				if (defined $defaults{$opt}) {
					$targets{_}{$opt} = $defaults{$opt};
				} else {
					delete $targets{_}{$opt};
				}
			} elsif (($tgt eq '^' || $tgt eq '$') && $val eq '') {
				delete $targets{$tgt}{$opt};
			} elsif ($opt eq 'options') {
				# Do not forget defaults [^] and [$]
				delete $targets{$tgt}{options};
				%{$targets{$tgt}{options}} = %{$targets{'^'}{options}}
					if defined $targets{'^'}{options};
				$val = lc($val);
				map { $targets{$tgt}{options}{$_} = 1 } ($val =~ m/([a-z]+)/g);
				%{$targets{$tgt}{options}} = (%{$targets{$tgt}{options}},
					%{$targets{'$'}{options}})
					if defined $targets{'$'}{options};
			} else {
				my $pre = $targets{'^'}{$opt}
					if defined $targets{'^'}{$opt};
				$pre ||= '';
				$targets{$tgt}{$opt} = $pre.$val;
				$targets{$tgt}{$opt} .= $targets{'$'}{$opt}
					if defined $targets{'$'}{$opt};
			}
			next;
		} elsif (/^Include\s*:\s*(\S*)$/) {
			push @all_config_files, $1;
			read_mrtg_config($1, $def, $cfgref, $order);
			next;
		} elsif (/^([\w\d]+)\s*:\s*(\S.*)$/) {
			my ($opt, $val) = (lc($1), $2);
			$cfgref->{$opt} = $val;
			next;
		}
		warn "Warning: Parse error in $file near $_\n" if $^W;
	}

	if (defined $cfgref->{pathadd}) {
		$ENV{PATH} .= ':'.$cfgref->{pathadd};
	}

#	if (defined $cfgref->{libadd}) {
#		use lib $cfgref->{libadd}
#	}
}

sub parse_directories {
	%directories = ();

	# FIXME: the sort is expensive
	for my $name (sort { $targets{$a}{order} <=> $targets{$b}{order} } keys %targets) {
		my $dir = $targets{$name}{directory}
			if defined $targets{$name}{directory};
		$dir = '' unless defined $dir;

		my $prefix = '';
		for my $component (split /\/+/, $dir) {
			unless (defined $directories{$prefix.$component}) {
				push (@{$directories{$prefix}{subdir}},
					$component);

				# For the directory, get the global parameters
				# from the # config of the first item of the
				# directory:
				$directories{$prefix}{config} =
					$targets{$name}{config};
				$directories{$prefix}{bodytag} =
					$targets{$name}{bodytag};
			}
			$prefix .= $component . '/';
		}
		unless (defined $directories{$dir}) {
			$directories{$dir}{config} =
				$targets{$name}{config};
			$directories{$dir}{bodytag} =
				$targets{$name}{bodytag};
		}

		push (@{$directories{$dir}{target}}, $name);
	}
}

sub print_dir($) {
	my ($dir) = @_;

	my $dir1 = $dir . '/';

	http_headers('text/html', $directories{$dir}{config});

	print <<EOF;
<HTML>
<HEAD>
<TITLE>MRTG: Directory $dir1</TITLE>
</HEAD>
EOF
	print $directories{$dir}{bodytag};

	my $subdirs_printed;
	if ($directories{$dir}{subdir} && @{$directories{$dir}{subdir}}) {
		$subdirs_printed = 1;
		print <<EOF;
<H1>MRTG subdirectories in the directory $dir1</H1>

<UL>
EOF
		for my $item (@{$directories{$dir}{subdir}}) {
			print "<LI><A HREF=\"$item/\">$item/</A>\n";
		}

		print "</UL>\n";
	}
	if ($directories{$dir}{target} && @{$directories{$dir}{target}}) {
		print "<HR>\n" if defined $subdirs_printed;
		print <<EOF;
<H1>MRTG graphs in the directory $dir1</H1>

<TABLE BORDER=0 WIDTH=100%>
EOF
		my $odd;
		for my $item (@{$directories{$dir}{target}}) {
			my $itemname = $item;
			$itemname = $targets{$item}{title}
				if defined $targets{$item}{title};
			print "    <TR>\n" unless $odd;
			print <<EOF;
   <TD><A HREF="$item.html">$itemname<BR>
	<IMG SRC="$item-day.$imagetype" BORDER=0 ALIGN=TOP VSPACE=10 ALT="$item">
	</A><BR CLEAR=ALL>
   </TD>
EOF
			print "    </TR>\n" if $odd;
			$odd = !$odd;
		}
		print "    </TR>\n</TABLE>\n";
	}

	print_banner($directories{$dir}{config});
	print "</BODY>\n</HTML>\n";
}

sub print_banner($) {
	my $cfg = shift;

	print <<EOF;

<HR>
<table BORDER=0 CELLSPACING=0 CELLPADDING=0>
<tr>
<td WIDTH=63><a ALT="MRTG"
    HREF="http://ee-staff.ethz.ch/~oetiker/webtools/mrtg/mrtg.html"><img
BORDER=0 SRC="$cfg->{icondir}/mrtg-l.$imagetype"></a></td>
<td WIDTH=25><a ALT=""
    HREF="http://ee-staff.ethz.ch/~oetiker/webtools/mrtg/mrtg.html"><img
BORDER=0 SRC="$cfg->{icondir}/mrtg-m.$imagetype"></a></td>
<td WIDTH=388><a ALT=""
    HREF="http://ee-staff.ethz.ch/~oetiker/webtools/mrtg/mrtg.html"><img
BORDER=0 SRC="$cfg->{icondir}/mrtg-r.$imagetype"></a></td>
</tr>
</table>
<spacer TYPE=VERTICAL SIZE=4>
<table BORDER=0 CELLSPACING=0 CELLPADDING=0 WIDTH=476>
<tr VALIGN=top>
<td ALIGN=LEFT><font FACE="Arial,Helvetica" SIZE=2>
version 2.9.17</font></td>
<td ALIGN=RIGHT><font FACE="Arial,Helvetica" SIZE=2>
<a HREF="http://ee-staff.ethz.ch/~oetiker/webtools/mrtg.html">Tobias Oetiker</a>
<a HREF="mailto:oetiker\@ee.ethz.ch">&lt;oetiker\@ee.ethz.ch&gt;</a>
</font></td>
</tr><tr>
<td></td>
<td ALIGN=RIGHT><font FACE="Arial,Helvetica" SIZE=2>
and&nbsp;<a HREF="http://www.bungi.com">Dave&nbsp;Rand</a>&nbsp;<a HREF="mailto:dlr\@bungi.com">&lt;dlr\@bungi.com&gt;</a></font>
</td>
<tr VALIGN=top>
<td ALIGN=LEFT><font FACE="Arial,Helvetica" SIZE=2>
<A HREF=http://www.fi.muni.cz/~kas/mrtg-rrd/>mrtg-rrd.cgi version $version</A>
</font></td>
<td ALIGN=RIGHT><font FACE="Arial,Helvetica" SIZE=2>
<A HREF="http://www.fi.muni.cz/~kas/">Jan "Yenya" Kasprzak</A>
<A HREF="mailto:kas\@fi.muni.cz">&lt;kas\@fi.muni.cz&gt;</A>
</font></td>
</tr>
</table>
EOF
	print '<!--$Id: mrtg-rrd.cgi,v 1.35 2003/08/18 15:58:57 kas Exp $-->', "\n";
}

sub dump_targets() {
	for my $tgt (keys %targets) {
		print "Target $tgt:\n";
		for my $opt (keys %{$targets{$tgt}}) {
			if ($opt eq 'options') {
				print "\toptions: ";
				for my $o1 (keys %{$targets{$tgt}{options}}) {
					print $o1, ",";
				}
				print "\n";
				next;
			}
			print "\t$opt: ", $targets{$tgt}{$opt}, "\n";
		}
	}
}

sub dump_directories {
	print "Directories:\n";

	for my $dir (keys %directories) {
		print "Directory $dir:\n";
		for my $item (@{$directories{$dir}}) {
			print "\t$item\n";
		}
	}
}

sub print_error(@)
{
	print "Content-Type: text/plain\n\nError: ", join(' ', @_), "\n";
	exit 0;
}

#--BEGIN CGI--
#For CGI, use this:

use CGI;
my $q = new CGI;

# thttpd fix up by Akihiro Sagawa
if ($q->server_software() =~ m|^thttpd/|) {
	my $path = $q->path_info();
	$path .= '/' if ($q->script_name=~ m|/$|);
	$q->path_info($path);
}

handler($q);

#--END CGI--
#--BEGIN FCGI--
# For FastCGI, uncomment this and comment out the above:
#-# use FCGI;
#-# use CGI;
#-#
#-# my $req = FCGI::Request();
#-#
#-# while ($req->Accept >= 0) {
#-# 	my $q = new CGI;
#-#
#-# 	# thttpd fix up by Akihiro Sagawa
#-# 	if ($q->server_software() =~ m|^thttpd/|) {
#-# 		my $path = $q->path_info();
#-# 		$path .= '/' if ($q->script_name=~ m|/$|);
#-# 		$q->path_info($path);
#-# 	}
#-#
#-# 	handler($q);
#-# }
#--END FCGI--

1;
