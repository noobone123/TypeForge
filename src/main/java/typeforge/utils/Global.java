package typeforge.utils;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.flatapi.FlatProgramAPI;
/**
 * The global state of the current analysis.
 */
public class Global {
    public static Program currentProgram;
    public static FlatProgramAPI flatAPI;
    public static GhidraScript ghidraScript;
    public static String outputDirectory;
    public static long startAddress;

    public static long typeAnalysisBeginTime;
    public static long typeAnalysisEndTime;
    public static long retypingBeginTime;
    public static long retypingEndTime;
    public static long prepareAnalysisBeginTime;
    public static long prepareAnalysisEndTime;
}
