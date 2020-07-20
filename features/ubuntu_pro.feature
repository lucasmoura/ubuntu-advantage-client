@uses.config.machine_type.pro.aws
Feature: Command behaviour when attached to an UA subscription

    @series.xenial
    @series.bionic
    @series.focal
    Scenario Outline: Attached refresh in a trusty machine
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I run `ua status --all` as non-root
        Then stdout matches regexp:
            """
            SERVICE       ENTITLED  STATUS    DESCRIPTION
            cc-eal        +<cc-eal> +<cc-eal-s>  +Common Criteria EAL2 Provisioning Packages
            cis-audit     +no       +—    +Center for Internet Security Audit Tools
            esm-apps      +yes +enabled +UA Apps: Extended Security Maintenance
            esm-infra     +yes     +enabled +UA Infra: Extended Security Maintenance
            fips          +<fips> +<fips-s> +NIST-certified FIPS modules
            fips-updates  +<fips> +<fips-s> +Uncertified security updates to FIPS modules
            livepatch     +yes      +enabled  +Canonical Livepatch service
            """
        Examples: ubuntu release
           | release | cc-eal | cc-eal-s | fips | fips-s   |
           | xenial  | yes    | disabled | yes  | disabled |
           | bionic  | yes    | n/a      | yes  | disabled |
