require "json"
require "rest_client"
require "addressable/uri"
require "cgi"
require "logger"

require "owasp_zap/version"
require "owasp_zap/error"
require "owasp_zap/string_extension"
require "owasp_zap/spider"
require "owasp_zap/attack"
require "owasp_zap/alert"
require "owasp_zap/auth"
require "owasp_zap/scanner"
require "owasp_zap/policy"

module OwaspZap
    class ZapException < Exception;end

    class Zap
       attr_accessor :target,:base, :zap_bin

       def initialize(params = {})
            #TODO
            # handle params
            @base = params[:base] || "http://127.0.0.1:8080"
            @target = params[:target]
            @zap_bin = params [:zap] || "#{ENV['HOME']}/ZAP/zap.sh"
            @output = params[:output] || $stdout #default we log everything to the stdout
        end

        def status_for(component)
            case component
            when :ascan
                ::Attack.new(:base=>@base,:target=>@target).status
            when :spider
                ::Spider.new(:base=>@base,:target=>@target).status
            when :scan
                ::Scan.new(:base=>@base,:target=>@target).status
            else
                {:status=>"unknown component"}.to_json
            end

        end
        def ok?(json_data)
            json_data.is_a?(Hash) and json_data[0] == "OK"
        end

        def running?
            begin
                response = RestClient::get "#{@base}"
            rescue Errno::ECONNREFUSED
                return false
            end
            response.code == 200
        end

        def policy
            ::Policy.new(:base=>@base)
        end

        def alerts
            ::Alert.new(:base=>@base,:target=>@target)
        end
        
        def scanner
            ::Scanner.new(:base=>@base)
        end

        #attack
        def ascan
            ::Attack.new(:base=>@base,:target=>@target)
        end

        def spider
            ::Spider.new(:base=>@base,:target=>@target)
        end

        def auth
            ::Auth.new(:base=>@base) 
        end

        # TODO
        # DOCUMENT the step necessary: install ZAP under $home/ZAP or should be passed to new as :zap parameter
        def start(params = {})
            cmd_line = if params.key? :daemon
                "#{@zap_bin} -daemon"
            else
                @zap_bin
            end
            fork do
               # if you passed :output=>"file.txt" to the constructor, then it will send the forked process output
               # to this file (that means, ZAP stdout)
               unless @output == $stdout
                STDOUT.reopen(File.open(@output, 'w+'))
                STDOUT.sync = true 
               end
               exec cmd_line
            end
        end

        #shutdown zap
        def shutdown
            RestClient::get "#{@base}/JSON/core/action/shutdown/"
        end

        #xml report
        #maybe it should be refactored to alert. 
        def xml_report
            RestClient::get "#{@base}/OTHER/core/other/xmlreport/"
        end
        
        def html_report
            RestClient::get "#{@base}/OTHER/core/other/htmlreport/"
        end
   end
end
