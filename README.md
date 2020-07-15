# IDS
Intrusion Detection System for all forms in Eprint

## DESCRIPTION

- plugin
- whitelist

## Installation
    
- install CPAN Module CGI::IDS from https://metacpan.org/release/CGI-IDS
- put plugin IDS.pm into your {eprints_root}/lib/plugins/EPrints/Plugin
- put YOUR_whitelist.xml into your {eprints_root}/archives/_REPO_/cfg/cfg.d directory
- edit all FILES and make your own PATH-configuration

## Example
    
- install in any .pl/cgi on top: 'check_ids();'

- E.g.: IRSTATS2 - cfg/plugins/EPrints/Plugin/Stats/View/_YOUR_REPORT_.pm

 ```
 [...]
 sub render_filters
 {
         # IDS against https://github.com/eprints/irstats2/issues/95
         EPrints::Plugin::IDS::check_ids();
         
 [...]
 ```

