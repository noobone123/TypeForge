import blueprint.solver.InterSolver;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import blueprint.base.graph.CallGraph;
import blueprint.utils.*;

import java.util.List;
import java.util.Set;

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

        InterSolver interSolver = new InterSolver(cg);
        interSolver.run();

        long endTime = System.currentTimeMillis();

        Logging.info("GhidraScript","Analysis time: " + (endTime - startTime) / 1000.00 + "s");
    }

    protected boolean prepareAnalysis() {
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
}