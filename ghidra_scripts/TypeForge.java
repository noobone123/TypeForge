import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import typeforge.solver.InterSolver;
import typeforge.base.graph.CallGraph;
import typeforge.solver.ReTyper;
import typeforge.utils.*;
import org.apache.commons.io.FileUtils;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.io.File;

public class TypeForge extends GhidraScript {
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

        long startAnalysisTime = System.currentTimeMillis();

        // Function node and CallGraph Statistics
        Set<Function> meaningfulFunctions = FunctionHelper.getMeaningfulFunctions();
        Logging.info("GhidraScript","Number of meaningful functions: " + meaningfulFunctions.size());

        CallGraph cg = CallGraph.getCallGraph();
        DataTypeHelper.buildNameToDTMap();

        InterSolver interSolver = new InterSolver(cg);
        interSolver.run();

        long endAnalysisTime = System.currentTimeMillis();

        ReTyper reTyper = new ReTyper(interSolver.generator.getFinalSkeletons(),
                                interSolver.generator.getExprToSkeletonMap());
        reTyper.run();

        long endReTypeTime = System.currentTimeMillis();

        Logging.warn("GhidraScript","Analysis time: " + (endAnalysisTime - startAnalysisTime) / 1000.00 + "s");
        Logging.warn("GhidraScript","ReType time: " + (endReTypeTime - endAnalysisTime) / 1000.00 + "s");
        Logging.warn("GhidraScript","Total time: " + (endReTypeTime - startAnalysisTime) / 1000.00 + "s");
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