package typeclay.solver;

import aQute.libg.glob.Glob;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import typeclay.base.dataflow.skeleton.Skeleton;
import typeclay.utils.Global;
import typeclay.utils.Logging;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * We First Utilize readability assessment method to generate final Skeleton info json base on following Skeleton_uuid_morph.json
 *
 * Skeleton_uuid_morph.json: {
 *     globalMorph: {
 *         type1: {
 *             layout: ...,
 *             ptrRelation: ...,
 *             nestRelation: ...,
 *             decompiledCodes: {
 *                  funcOffset: decompiledCode,
 *                  //
 *             },
 *         },
 *         type2: {
 *             primTyoe: char,
 *             decompiledCodes: {
*  *                  funcOffset: decompiledCode,
*  *                  //
 *  *          },
 *         },
 *         ...
 *     },
 *     rangeMorph: [
 *         {
 *             startOffset: 0x00,
 *             endOffset:   0x00,
 *             types: {
 *                 type1: {
     *  *             layout: ...,
     *  *             ptrRelation: ...,
     *  *             nestRelation: ...,
     *  *             decompiledCodes: {
     *  *                  funcOffset: decompiledCode,
     *  *                  //
     *  *             },
     *  *          },
 *                 type2: {
 *                      //
 *                 }
 *             }
 *         }
 *     ]
 * }
 *
 *
 * For variable type recovery, we generate following json file:
 * VarType.json: {
 *   FunctionOffset: {
 *       "Parameters": {
 *          "param_0": {
 *              "desc": "Pointer",
 *              "ptrLevel": 1,
 *              "type": "Skeleton_uuid"
 *          },
 *       },
 *       "LocalVariables": {
 *           "Stack[-24]" : {
 *              "desc": Pointer,
 *              "ptrLevel": 1,
 *              "type": "Skeleton_uuid"
 *           },
 *           Register[0013d268]: {
 *               "desc": Local,
 *               "type": "Skeleton_uuid"
 *           }
 *           ,
 *       }
 *   }
 * }
 *
 */
public class ReTyper {

    Set<Skeleton> sktSet = new HashSet<>();
    ObjectMapper mapper = new ObjectMapper();

    public ReTyper(Set<Skeleton> skeletons) {
        sktSet.addAll(skeletons);
    }

    public void run() {
        prepare();

        for (var skt: sktSet) {
            var jsonRoot = generateJson(skt);
            var filePath = Global.outputDirectory + "/" + skt.toString() + "_orig.json";
            saveJsonToFile(filePath, jsonRoot);
        }
    }


    public ObjectNode generateJson(Skeleton skt) {
        var jsonRoot = mapper.createObjectNode();
        var layout = mapper.createObjectNode();
        var ptrRelation = mapper.createObjectNode();
        var nestRelation = mapper.createObjectNode();
        var globalMorph = mapper.createObjectNode();
        var rangeMorph = mapper.createArrayNode();

        writeLayout(skt, layout);


        jsonRoot.set("layout", layout);
        jsonRoot.set("ptrRelation", ptrRelation);
        jsonRoot.set("nestRelation", nestRelation);
        jsonRoot.set("globalMorph", globalMorph);
        jsonRoot.set("rangeMorph", rangeMorph);

        return jsonRoot;
    }

    private void writeLayout(Skeleton skt, ObjectNode layout) {
        if (skt.noMorphingTypes() && skt.finalType != null) {
            layout.put("")
        }
    }


    private void prepare() {
        var outputDirStr = Global.outputDirectory;
        var outputDir = new File(outputDirStr);
        /* If the output directory does not exist, create it; otherwise, delete all files in it */
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        } else {
            var files = outputDir.listFiles();
            if (files != null) {
                for (var file : files) {
                    file.delete();
                }
            }
        }
    }


    private void saveJsonToFile(String fileName, ObjectNode jsonRoot) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(new File(fileName), jsonRoot);
            Logging.info("GhidraScript", "Successfully wrote JSON to file: " + fileName);
        } catch (IOException e) {
            Logging.error("GhidraScript", "Error writing JSON to file: " + e.getMessage());
        }
    }
}
