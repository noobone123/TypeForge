import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;

import blueprint.base.CallGraph;
import blueprint.utils.GlobalState;
import blueprint.utils.Logging;

public class statistics extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Statistics for " + currentProgram.getName());
        println("Number of functions: " + currentProgram.getFunctionManager().getFunctionCount());
        println("Number of instructions: " + currentProgram.getListing().getNumInstructions());
        println("Number of bytes: " + currentProgram.getMemory().getSize());

        if(!Logging.init()) {
            return;
        }

        if (!prepareAnalysis()) {
            return;
        }


    }

    protected boolean prepareAnalysis() {
        GlobalState.currentProgram = this.currentProgram;
        GlobalState.flatAPI = this;
        Language language = this.currentProgram.getLanguage();
        if (language == null) {
            Logging.error("Language not found");
            return false;
        } else {
            Logging.info("Language: " + language.getLanguageID());
            return true;
        }
    }
}