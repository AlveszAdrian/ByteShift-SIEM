export namespace main {
	
	export class LogConfig {
	    manager_ip: string;
	    file_paths: string[];
	    syslog_port: number;
	    win_events: string[];
	
	    static createFrom(source: any = {}) {
	        return new LogConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.manager_ip = source["manager_ip"];
	        this.file_paths = source["file_paths"];
	        this.syslog_port = source["syslog_port"];
	        this.win_events = source["win_events"];
	    }
	}

}

