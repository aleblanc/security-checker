Packagist Security Checker from Github advisory database
===========================

Use [Github advisory database][1] for perform a [Symfony][2] security check.

[1]: https://github.com/github/advisory-database
[2]: https://symfony.com/

## Installation / use :

<pre>
composer require aleblanc/security-checker --dev
php vendor/aleblanc/security-checker/security-checker security:check
</pre>

## Perform a security scan with Github Actions / Github CI from Github advisory database

<pre>
  api_security_checker_github:
    name: Github Advisory Security checker (PHP ${{ matrix.php }})
    runs-on: ubuntu-latest
    timeout-minutes: 20
    strategy:
      matrix:
        php:
          - '8.1'
      fail-fast: false
    steps:
      - name: Checkout
        uses: actions/checkout@v3
        with:
          token: "${{ secrets.GITHUB_TOKEN }}"
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: ${{ matrix.php }}
          extensions: intl, bcmath, curl, openssl, mbstring, zip
          ini-values: memory_limit=-1
          tools: pecl, composer
          coverage: none
      - run: composer require aleblanc/security-checker --dev
      - run: php vendor/aleblanc/security-checker/security-checker security:check
</pre>


Fork from https://github.com/sensiolabs/security-checker
