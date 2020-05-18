=begin
    Copyright 2010-2017 Sarosys LLC <http://www.sarosys.com>

    This file is part of the Arachni Framework project and is subject to
    redistribution and commercial restrictions. Please see the Arachni Framework
    web site for more information on licensing and terms of use.
=end

# Looks for sensitive common files on the server.
#
# @author Tasos "Zapotek" Laskos <tasos.laskos@arachni-scanner.com>
class Arachni::Checks::CommonFiles < Arachni::Check::Base

    def self.filenames(page_platforms)
        sorted_wordlists = {}
        Dir.each_child(get_dir()) do |filename|
            file_platform = filename.split(".")[0]
            sorted_wordlists[file_platform]||= []
            sorted_wordlists[file_platform].push(filename)
        end

        wordlist = []
        sorted_wordlists.each do |platform,wordlists|
            if platform == "any" || page_platforms.include?(platform.to_sym)
                wordlists.each{ |filename| wordlist+=read_file(filename) }
            end
        end
        return wordlist
    end

    def run
        return if page.code != 200

        # Runs the check only once (at the given path) because sorted_wordlists
        # are made to be executed at the root for pre existing directories  
        @framework.checks.delete(self.shortname)

        path = get_path( page.url )
        return if audited?( path )

        self.class.filenames(page.platforms.to_a).each { |file| log_remote_file_if_exists( path + file ) }
        audited( path )
    end

    def self.info
        {
            name:             'Common files',
            description:      %q{Tries to find common sensitive files on the server.},
            elements:         [ Element::Server ],
            author:           'Tasos "Zapotek" Laskos <tasos.laskos@arachni-scanner.com> ',
            version:          '0.2.4',
            platforms: Arachni::Platform::Manager::FRAMEWORKS,

            issue:       {
                name:            %q{Common sensitive file},
                description:     %q{
Web applications are often made up of multiple files and directories.

It is possible that over time some files may become unreferenced (unused)
by the web application and forgotten about by the administrator/developer.
Because web applications are built using common frameworks, they contain common
files that can be discovered (independent of server).

During the initial recon stages of an attack, cyber-criminals will attempt to
locate unreferenced files in the hope that the file will assist in further
compromise of the web application.
To achieve this they will make thousands of requests using word lists containing
common filenames.
The response headers from the server will then indicate if the file exists.

Arachni also contains a list of common file names which it will attempt to access.
},
                references: {
                    'Apache.org' => 'http://httpd.apache.org/docs/2.0/mod/mod_access.html'
                },
                tags:            %w(common path file discovery),
                severity:        Severity::LOW,
                remedy_guidance: %q{
If files are unreferenced then they should be removed from the web root
and/or the application directory.

Preventing access without authentication may also be an option and can stop a
client from being able to view the contents of a file, however it is still likely
that the directory structure will be able to be discovered.

Using obscure file names is implementing security through obscurity and is
not a recommended option.
}
            }
        }
    end
end
