import blueprint.solver.InterSolver;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import blueprint.base.graph.CallGraph;
import blueprint.utils.*;
import org.apache.commons.io.FileUtils;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.io.File;

public class BluePrint extends GhidraScript {
    @Override
    protected void run() throws Exception {

        if(!Logging.init()) {
            return;
        }
        if (!prepareAnalysis()) {
            return;
        }

        List<Function> functions = Global.currentProgram.getListing().getGlobalFunctions("main");
        if (functions.isEmpty()) {
            Logging.error("GhidraScript","No main function found");
            return;
        }
        Logging.info("GhidraScript","Number of main functions: " + functions.size());

        long startTime = System.currentTimeMillis();

        // Function node and CallGraph statistics
        Set<Function> meaningfulFunctions = FunctionHelper.getMeaningfulFunctions();
        Logging.info("GhidraScript","Number of meaningful functions: " + meaningfulFunctions.size());

        CallGraph cg = CallGraph.getCallGraph();
        DataTypeHelper.buildNameToDTMap();

        InterSolver interSolver = new InterSolver(cg);
        interSolver.run();

        long endTime = System.currentTimeMillis();

        Logging.info("GhidraScript","Analysis time: " + (endTime - startTime) / 1000.00 + "s");
    }

    protected boolean prepareAnalysis() {
        parseArgs();
        prepareOutputDirectory();

        Global.currentProgram = this.currentProgram;
        Global.flatAPI = this;
        Global.ghidraScript = this;

        Language language = this.currentProgram.getLanguage();
        if (language == null) {
            Logging.error("GhidraScript","Language not found");
            return false;
        } else {
            Logging.info("GhidraScript","Language: " + language.getLanguageID());
            return true;
        }
    }

    protected void parseArgs() {
        String[] args = getScriptArgs();
        for (String arg : args) {
            Logging.info("GhidraScript", "Arg: " + arg);
            // split the arguments string by "="
            String[] argParts = arg.split("=");
            if (argParts.length != 2) {
                Logging.error("GhidraScript", "Invalid argument: " + arg);
                System.exit(1);
            }

            String key = argParts[0];
            String value = argParts[1];

            if (key.equals("output")) {
                Global.outputDirectory = value;
            } else if (key.equals("start_addr")) {
                Global.startAddress = Long.decode(value);
            } else {
                Logging.error("GhidraScript", "Invalid argument: " + arg);
                System.exit(1);
            }
        }
    }

    protected void prepareOutputDirectory() {
        if (Global.outputDirectory == null) {
            Logging.error("GhidraScript","Output directory not specified");
            System.exit(1);
        }

        File outputDir = new File(Global.outputDirectory);
        // If the output directory does not exist, create it
        if (!outputDir.exists()) {
            if (!outputDir.mkdirs()) {
                Logging.error("GhidraScript", "Failed to create output directory");
                System.exit(1);
            }
        } else {
            try {
                FileUtils.cleanDirectory(outputDir);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}