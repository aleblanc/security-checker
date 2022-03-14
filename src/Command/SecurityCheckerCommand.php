<?php


namespace SensioLabs\Security\Command;

use SensioLabs\Security\Exception\ExceptionInterface;
use SensioLabs\Security\SecurityChecker;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class SecurityCheckerCommand extends Command
{
    protected static $defaultName = 'al:security:check';

    private $checker;

    public function __construct(SecurityChecker $checker)
    {
        $this->checker = $checker;

        parent::__construct();
    }

    /**
     * @see Command
     */
    protected function configure()
    {
        $this
            ->setName('al:security:check')
            ->setDefinition([
                new InputArgument('lockfile', InputArgument::OPTIONAL, 'The path to the composer.lock file', 'composer.lock')
            ])
            ->setDescription('Checks security issues in your project dependencies')
            ->setHelp(<<<EOF
The <info>%command.name%</info> command looks for security issues in the
project dependencies:

<info>php %command.full_name%</info>

You can also pass the path to a <info>composer.lock</info> file as an argument:

<info>php %command.full_name% /path/to/composer.lock</info>

By default, the command displays the result in plain text, but you can also
configure it to output JSON instead by using the <info>--format</info> option:

<info>php %command.full_name% /path/to/composer.lock --format=json</info>
EOF
            );
    }

    /**
     * @see Command
     * @see SecurityChecker
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        try {
            $vulnerabilities = $this->checker->check($input->getArgument('lockfile'));
        } catch (ExceptionInterface $e) {
            $output->writeln($this->getHelperSet()->get('formatter')->formatBlock($e->getMessage(), 'error', true));

            return 1;
        }
        

        $output->writeln("<comment>Dependabot Github Security Check Report</comment>");
        $output->writeln("<comment>=======================================</comment>");
        $output->writeln("");
        if(count($vulnerabilities)>0){
            $output->writeln("<error>".count($vulnerabilities)." packages have known vulnerabilities</error>");
            $output->writeln("");
            foreach($vulnerabilities as $key=>$vuls){
                $output->writeln("");
                $output->writeln("<comment>".$key."</comment>");
                $output->writeln("");
                foreach($vuls as $vul){
                    $output->writeln("<options=bold,underscore> * [".$vul["data"]->database_specific->severity.' severity] '.$vul["data"]->id.': '.$vul["data"]->summary."</>");
                    $output->writeln("");
                    foreach($vul["data"]->references as $reference){
                        $output->writeln(' - <href='.$reference->url.'>'.$reference->url.'</>');
                    }
                }
            }
        }else{
            $output->writeln("<info>No packages have known vulnerabilities.</info>");
        }
    
        
        if (\count($vulnerabilities) > 0) {
            return 1;
        }

        return 0;
    }
}
