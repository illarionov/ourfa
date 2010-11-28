use Test::More tests => 5;
use Data::Dumper;
BEGIN { use_ok('Ourfa');
};

my $sslctx = Ourfa::SSLCtx->new();

ok(defined $sslctx,               'SSLCtx new() OK');
ok($sslctx->isa('Ourfa::SSLCtx'), 'class');

can_ok($sslctx, qw/ssl_type cert load_cert key cert_pass
   load_private_key get_ctx/);

my $ssl_type = $sslctx->ssl_type;

ok( $ssl_type =~ /^[0-9]+$/, "ssl_type is number");

diag("ssl_type: $ssl_type");

my $ssl_type2 = $sslctx->ssl_type(Ourfa::OURFA_SSL_TYPE_RSA_CRT);

diag("ssl_type2: $ssl_type2");

