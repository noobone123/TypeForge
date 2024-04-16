package blueprint.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighVariable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.xml.XmlConfiguration;

/**
 * Logging class.
 */
public class Logging {

    private static final String DEFAULT_LOGGER_NAME = "BluePrint";
    private static final String DEFAULT_CONFIG_FILE_PATH = "/log4j2_default.xml";
    private static Logger defaultLogger;

    /**
     * Initialize the logging module.
     * @return true if init success, false otherwise.
     */
    public static boolean init() {
        InputStream in = Logging.class.getResourceAsStream(DEFAULT_CONFIG_FILE_PATH);
        try {
            assert in != null;
            Configuration configuration = new XmlConfiguration(new LoggerContext(DEFAULT_LOGGER_NAME),
                    new ConfigurationSource(in));
            LoggerContext context = (LoggerContext) LogManager.getContext(true);
            context.stop();
            context.start(configuration);
            defaultLogger = context.getLogger(DEFAULT_LOGGER_NAME);
        } catch (IOException e) {
            System.out.println("Cannot locate logging config file :" + in);
            return false;
        }
        return true;
    }

    /**
     * Generate an error log.
     * @param msg the log message.
     */
    public static void error(String msg) {
        defaultLogger.error(msg);
    }

    /**
     * Generate a warning log.
     * @param msg the log message.
     */
    public static void warn(String msg) {
        defaultLogger.warn(msg);
    }

    /**
     * Generate a info log.
     * @param msg the log message.
     */
    public static void info(String msg) {
        defaultLogger.info(msg);
    }

    /**
     * Generate a debug log
     * @param msg the debug log.
     */
    public static void debug(String msg) {
        defaultLogger.debug(msg);
    }


    public static void collectTypeLog(HighVariable highVar, Long offset, DataType dataType) {
        String msg = String.format("[Collector] HighVariable: %s, Offset: 0x%x, DataType: %s, Size: 0x%x",
                highVar.getName(), offset, dataType.getName(), dataType.getLength());
        Logging.info(msg);
    }
}