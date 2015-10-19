ourfa
=====

библиотека доступа к функциям биллинга UTM на C.
В библиотеке реализован протокол взаимодействия с биллингом на сетевом уровне,
а так же интерфейс для работы с его XML API схемами.

На основе этой библиотеки созданы приложения:

**ourfa_client** — аналог официального консольного клиента `utm5_urfaclient`.
Выполняет те же функции и работает с теми же XML схемами. Но имеет несколько
дополнительных возможностей, например, вывод результатов не в XML.

**ourfa-perl** - XS библиотека, интерфейс для доступа к биллингу на perl.

Основное обсуждение ведется на форумах UTM:
<http://www.netup.ru/phpbb/viewtopic.php?t=7485>

Версия: ** 521008002.2 (31 марта 2011) **

#### Ссылки

* Исходный код: [ourfa-521008002.2.tar.gz](https://github.com/downloads/littlesavage/ourfa/ourfa-521008002.2.tar.gz)
* Все файлы: [downloads](https://github.com/littlesavage/ourfa/downloads)


Сборка и установка
------------------

Требуются библиотеки xml2, ssl, iconv. В debian-based
дистрибутивах для сборки нужно установить `-dev` пакеты:

    $ sudo apt-get install libxml2-dev libssl-dev

Сборка в общем случае:

     $ make
     $ su
     # make install

При этом устанавливается сама библиотека (`ourfa.h`, `libourfa.a`) и `ourfa_client`.

В современных дистрибутивах `linux` не требуется `libiconv` и собирать нужно
без -liconv: `make install ICONV_LIBS=""`  

В `linux` устанавливать лучше не через `makе install`, а через
`checkinstall`.  

В `deb-based linux` можно собрать пакет:

    $ sudo apt-get install build-essential devscripts debhelper
    $ debuild -i -us -uc -b


**ourfa-perl** ставится отдельно, только при необходимости. Для его сборки требуется установленная основная библиотека (описано выше).

    cd ourfa-perl
    make
    make test
    make install


Использование
-------------

### ourfa_client

Работа похожа на работу с официальным `urfa_client`, поэтому лучше сначала 
ознакомиться с официальной документаций. Но есть много отличий.

      usage: ourfa_client -a action 
       [-H addr] [-p port] [-l login] [-P pass] [-api api.xml] [-h]

     -help      This message
     -a         Action name
     -H         URFA server host (default: localhost)
     -p         URFA server port (default: 11758)
     -l         URFA server login. (default: init)
     -P         URFA server password. (default: init)
     -c         Config file (default: /netup/utm5/utm5_urfaclient.cfg)
     -s         Restore session with ID
     -i         Restore session with IP
     -S         SSL/TLS method: none (default), tlsv1, sslv3, cert, rsa_cert
     -C         Certificate file for rsa_cert SSL (PEM format)
     -k         Private key file for rsa_cert SSL (PEM format)
     -x         URFA server xml dir. (default: /netup/utm5/xml)
     -u         Login as user (not admin)
     -dealer    Login as dealer (not admin)
    -timeout   Timeout in seconds (default: 30)
    -is_in_unicode Turn off conversion of command line arguments to unicode
    -o         Output format: xml (default), batch, or hash
    -debug     Turn on debug
    -datafile  Load array datas from file
    -api       URFA server API file (default: api.xml)
    -<param>[:idx] Set input parameter param(idx)


С версии UTM 5.2.1-008 запускать утилиту нужно обязательно с SSL и сертификатом.
Сертификат можно найти на вики [urfaclient на PHP](http://wiki.flintnet.ru/doku.php/urfaclient_php).
Можно просто скачать `admin.crt` в `/netup/UTM5/admin.crt` и запускать
`ourfa_client` с аргументом `-s rsa_cert`

Каталог со схемой api.xml должен быть именно от той версии UTM, которая
используется в системе (задается ключом `-x`, по умолчанию
`/netup/utm5/xml`). Схема читается из `api.xml` и
если использовать её из другой версии, то формат аргументов вызываемых функций 
может не совпасть.

Пример вызова, выполнение функции `rpcf_core_version`:

    ./ourfa_client -S rsa_cert -H localhost -l admin -P admin -a rpcf_core_version
    Loading config file /netup/utm5/utm5_urfaclient.cfg
    Loading API XML: /netup/utm5/xml/api.xml
    <?xml version="1.0"?>
    <urfa>
      <session key="94fe235600000000e59ddc990b8d1ffd"/>
      <call function="rpcf_core_version">
        <output>
          <string name="core_version" value="5.3"/>
        </output>
      </call>
    </urfa>

