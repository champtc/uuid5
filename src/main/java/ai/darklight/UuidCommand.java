package ai.darklight;

import java.util.UUID;

import org.json.JSONObject;

import io.micronaut.configuration.picocli.PicocliRunner;
import io.micronaut.context.ApplicationContext;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "uuid", description = "herp", mixinStandardHelpOptions = true)
public class UuidCommand implements Runnable {

    @Option(names = {"-n", "--namespace"}, required = true, description = "The namespace to prepend to the JSON data")
    String namespace;
    
    @Option(names = {"-j", "--json"}, required = true, description = "The JSON data to use in the SHA-1 hashing function of UUID 5")
    String json;

    @Option(names = {"-f", "--filter"}, description = "Optional field used to filter down the JSON data by passing in a comma separated list of keys to keep from the JSON data")
    String filter = "";

    public static void main(String[] args) throws Exception {
    	ApplicationContext applicationContext = ApplicationContext.builder().deduceEnvironment(false).start();
        PicocliRunner.run(UuidCommand.class, applicationContext, args);
        applicationContext.close();
    }

    public void run() {
        
        if (namespace != null && json != null) {
        	UUID ns = UUID.fromString(namespace);
        	JSONObject j = new JSONObject(json);
        	UUID uuid = UUID5.generateDeterministicId(ns, j.toString(), filter);
        	System.out.println(uuid);
        }
        
    }
}
