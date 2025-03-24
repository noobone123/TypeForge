import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import typeforge.analyzer.TypeAnalyzer;
import typeforge.base.graph.CallGraph;
import typeforge.utils.*;
import org.apache.commons.io.FileUtils;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.io.File;

public class TypeForge extends GhidraScript {
    @Override
    protected void run() throws Exception {

        println("====================== TypeForge ======================");

        if(!Logging.init()) {
            return;
        }
        if (!prepare()) {
            return;
        }

        List<Function> functions = Global.currentProgram.getListing().getGlobalFunctions("main");
        DataTypeHelper.prepare();

        if (functions.isEmpty()) {
            Logging.error("TypeForge","No main function found");
            return;
        }
        Logging.info("TypeForge","Number of main functions: " + functions.size());

        long startAnalysisTime = System.currentTimeMillis();

        // Function node and CallGraph Statistics
        Set<Function> meaningfulFunctions = FunctionHelper.getMeaningfulFunctions();
        Logging.info("TypeForge","Number of meaningful functions: " + meaningfulFunctions.size());

        CallGraph cg = CallGraph.getCallGraph();

        Global.typeAnalysisBeginTime = System.currentTimeMillis();
        TypeAnalyzer analyzer = new TypeAnalyzer(cg);
        analyzer.run();
        Global.typeAnalysisEndTime = System.currentTimeMillis();

        Global.retypingBeginTime = System.currentTimeMillis();
//        ReTyper reTyper = new ReTyper(interSolver.generator.getFinalSkeletons(),
//                                interSolver.generator.getExprToSkeletonMap());
//        reTyper.run();
        Global.retypingEndTime = System.currentTimeMillis();


        Logging.warn("TypeForge","Type Analysis time: " + (Global.typeAnalysisEndTime - Global.typeAnalysisBeginTime) / 1000.00 + "s");
        Logging.warn("TypeForge","ReTyping time: " + (Global.retypingEndTime - Global.retypingBeginTime) / 1000.00 + "s");
        Logging.warn("TypeForge","Total time: " + (Global.retypingEndTime  - Global.typeAnalysisBeginTime) / 1000.00 + "s");
        Logging.warn("TypeForge", "Prepare Analysis time: " + (Global.prepareAnalysisEndTime - Global.prepareAnalysisBeginTime) / 1000.00 + "s");
    }

    protected boolean prepare() {
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