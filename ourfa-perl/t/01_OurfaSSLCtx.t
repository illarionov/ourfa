use Test::More tests => 17;
use Data::Dumper;
BEGIN { use_ok('Ourfa');
};

my $sslctx = Ourfa::SSLCtx->new();

ok(defined $sslctx,               'SSLCtx new() OK');
ok($sslctx->isa('Ourfa::SSLCtx'), 'class');

can_ok($sslctx, qw/ssl_type cert load_cert key cert_pass
   load_private_key get_ctx/);

#ssl_type
my $ssl_type = $sslctx->ssl_type;
ok( $ssl_type =~ /^[0-9]+$/, "ssl_type is number");
is($sslctx->ssl_type(OURFA_SSL_TYPE_RSA_CRT), OURFA_SSL_TYPE_RSA_CRT, "set OURFA_SSL_TYPE_RSA_CRT");
is($sslctx->ssl_type(), OURFA_SSL_TYPE_RSA_CRT, "ssl_type after set");
eval {$sslctx->ssl_type(100);};
ok($@ or warn , "ssl_type=100");
is($sslctx->ssl_type(), OURFA_SSL_TYPE_RSA_CRT, "ssl_type RSA_CRT");
is($sslctx->ssl_type(OURFA_SSL_TYPE_SSL3), OURFA_SSL_TYPE_SSL3,"OURFA_SSL_TYPE_SSL3");
is($sslctx->ssl_type(), OURFA_SSL_TYPE_SSL3, "set OURFA_SSL_TYPE_RSA");

#cert
my $cert =  $sslctx->cert;
ok(defined $cert);
ok($cert ne '');
diag("cert: $cert");

#TODO: load_cert

#key
my $key = $sslctx->key;
ok(defined $key);
ok($key ne '');
diag("key: $key");

#cert_pass
my $cert_pass = $sslctx->cert_pass;
ok(defined $cert_pass);
diag("cert_pass: ", $cert_pass);

#TODO: load_private_key

my $ctx = $sslctx->get_ctx();
ok(defined $ctx);

