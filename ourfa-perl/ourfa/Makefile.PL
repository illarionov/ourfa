use ExtUtils::MakeMaker;
$Verbose = 1;

my $xml2_includes=`xml2-config --cflags`;
my $xml2_libs = `xml2-config --libs`;


WriteMakefile(
   NAME   => 'Ourfa::libourfa',
   SKIP   => [qw(all static static_lib dynamic dynamic_lib)],
   LIBS              => ["-lssl $xml2_libs"], # e.g., '-lm'
   DEFINE            => $xml2_includes, # e.g., '-DHAVE_SOMETHING'
   clean  => {'FILES' => 'libourfa$(LIB_EXT)'},
);

sub MY::top_targets {
   '
all :: static

pure_all :: static

static ::       libourfa$(LIB_EXT)

libourfa$(LIB_EXT): $(O_FILES)
	 $(AR) cr libourfa$(LIB_EXT) $(O_FILES)
	 $(RANLIB) libourfa$(LIB_EXT)
   ';
}

