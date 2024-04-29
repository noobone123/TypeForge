package blueprint.solver;

import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.TypeBuilder;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;
import blueprint.base.dataflow.PointerRef;

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 * Each IntraSolver holds a Context.
 */
public class Context {

    public FunctionNode funcNode;

    /** The map from HighSymbol to TypeBuilder in the current context */
    public final HashMap<HighSymbol, TypeBuilder> typeBuilderMap;

    /** We only collect data-flow related to interested varnodes */
    public final HashSet<Varnode> interestedVn;

    /** Dataflow facts collected from the current function, each varnode may hold PointerRef from different base varnode and offset */
    public HashMap<Varnode, KSet<PointerRef>> dataFlowFacts;
    public int dataFlowFactKSize = 10;

    /** This aliasMap should be traced recursively manually, for example: a->b, b->c, but a->c will not be recorded */
    public UnionFind<HighSymbol> symbolAliasMap;

    /** These 2 maps are used to record the DataType's load/store operation on insteseted varnodes */
    public HashMap<PointerRef, DataType> loadMap;
    public HashMap<PointerRef, DataType> storeMap;


    public Context(FunctionNode funcNode) {
        this.funcNode = funcNode;
        this.typeBuilderMap = new HashMap<>();
        this.interestedVn = new HashSet<>();
        this.dataFlowFacts = new HashMap<>();
        this.symbolAliasMap = new UnionFind<>();
        this.loadMap = new HashMap<>();
        this.storeMap = new HashMap<>();
    }


    /**
     * Initialize the dataFlowFacts using the interested HighSymbols
     * @param candidates the HighSymbols that need to collect data-flow facts
     */
    public void initDataFlowFacts(List<HighSymbol> candidates) {
        // Update the interestedVn
        for (var candidate: candidates) {
            var highVar = candidate.getHighVariable();
            Logging.info("Candidate HighSymbol: " + candidate.getName());

            // If a HighSymbol (like a parameter) is not be used in the function, it can not hold a HighVariable
            if (highVar == null) {
                Logging.warn(funcNode.value.getName() + " -> HighSymbol: " + candidate.getName() + " has no HighVariable");
                continue;
            }

            // Add all varnode instances of the HighVariable to the interestedVn
            interestedVn.addAll(Arrays.asList(highVar.getInstances()));

            // Initialize the dataFlowFacts using the interested varnodes
            // TODO: This may cause flow-insensitive
            for (var vn: highVar.getInstances()) {
                var startVn = highVar.getRepresentative();
                var ptrRef = new PointerRef(vn, startVn, 0);
                dataFlowFacts.put(vn, new KSet<>(dataFlowFactKSize));
                dataFlowFacts.get(vn).add(ptrRef);
            }
        }
    }

    /**
     * If the PCodeOp's input varnodes is related to the interested varnode, then we should handle it.
     * @param pcode the PCodeOp
     * @return true if the PCodeOp is related to the interested varnode
     */
    public boolean isInterestedPCode(PcodeOpAST pcode) {
        for (var vn: pcode.getInputs()) {
            if (interestedVn.contains(vn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Update the dataflow facts with the new reference varnode.
     * Be careful, some varnode looks identical, but actually they have different uniqueId.
     * So they are different varnodes.
     * @param cur the current varnode which indicates the reference
     * @param base the base varnode in the PointerRef
     * @param offset the offset between newRef and base
     */
    public void updateDataFlowFacts(Varnode cur, Varnode base, long offset) {
        var newPtrRef = new PointerRef(cur, base, offset);
        var curDataFlowFact = dataFlowFacts.computeIfAbsent(cur, k -> new KSet<>(dataFlowFactKSize));
        curDataFlowFact.add(newPtrRef);
    }

    public void updateLoadStoreMap(PointerRef ptrRef, DataType dt, boolean isLoad) {
        if (isLoad) {
            loadMap.put(ptrRef, dt);
            Logging.debug("[Load] Update load map: " + ptrRef + " -> " + dt);
        } else {
            storeMap.put(ptrRef, dt);
            Logging.debug("[Store] Update store map: " + ptrRef + " -> " + dt);
        }
    }

    public KSet<PointerRef> getDataFlowFact(Varnode vn) {
        var res = dataFlowFacts.get(vn);
        if (res == null) {
            Logging.warn("Failed to get dataflow fact for " + vn);
            return null;
        }
        return res;
    }

    public void updateInterested(Varnode vn) {
        if (interestedVn.add(vn)) {
            Logging.debug("[Interested] Add interested varnode: " + vn);
        }
    }


    /**
     * Update the TypeBuilder based on the current context.
     * The TypeBuilder is used to store the dataflow facts of the HighSymbol.
     * The dataflow facts are stored in the fieldMap of the TypeBuilder.
     */
    public void updateTypeBuilder() {
        loadMap.forEach((ptrRef, dt) -> {
            var vn = ptrRef.base;
            var highSym = vn.getHigh().getSymbol();
            if (highSym == null) {
                Logging.warn("Failed to get HighSymbol for " + vn);
                return;
            }
            addField(highSym, ptrRef.offset, dt);
        });

        storeMap.forEach((ptrRef, dt) -> {
            var vn = ptrRef.base;
            var highSym = vn.getHigh().getSymbol();
            if (highSym == null) {
                Logging.warn("Failed to get HighSymbol for " + vn);
                return;
            }
            addField(highSym, ptrRef.offset, dt);
        });


        // handle highSymbol alias
        // If two highSymbols are alias, then they will share the same TypeBuilder
        // TODO: merge to which TypeBuilder? currently we merge to the TypeBuilder which used as the argument
        typeBuilderMap.forEach((highSym, typeBuilder) -> {
            HighSymbol root = symbolAliasMap.find(highSym);
            if (root != highSym) {

            }
        });
    }


    /**
     * Add a field to the current context. The field can be a primitive data type.
     * @param highSym the HighSymbol representing the variable that holds this structure type
     * @param offset the offset of the field within the structure
     * @param dt the field's data type if adding a DataType
     */
    public void addField(HighSymbol highSym, long offset, DataType dt) {
        typeBuilderMap.computeIfAbsent(highSym, k -> new TypeBuilder()).addPrimitive(offset, dt);
    }

    public void addField(HighSymbol highSym, long offset, TypeBuilder builder) {
        typeBuilderMap.computeIfAbsent(highSym, k -> new TypeBuilder()).addTypeBuilder(offset, builder);
    }

    /**
     * Merge the TypeBuilder of the other intraSolver's context to the current context.
     * @param other the callee intraSolver's context
     * @param from the HighSymbol in the other context
     * @param to the HighSymbol in the current context
     * @param offset the offset of `to` highSymbol's field
     * @return true if the merge is successful
     */
    public boolean updateTypeBuilderFromCallee(Context other, HighSymbol from, HighSymbol to, long offset) {
        if (!other.typeBuilderMap.containsKey(from)) {
            Logging.error("No HighSymbol in the other context");
            return false;
        }

        var otherTypeBuilder = other.typeBuilderMap.get(from);
        if (offset == 0) {
            typeBuilderMap.put(to, otherTypeBuilder);
            otherTypeBuilder.addTag(0, "ARGUMENT");
        } else {
            var typeBuilder = typeBuilderMap.computeIfAbsent(to, k -> new TypeBuilder());
            typeBuilder.addTypeBuilder(offset, otherTypeBuilder);
            typeBuilder.addTag(offset, "ARGUMENT");
        }

        return true;
    }

    /**
     * If two highSymbols are alias intra-procedural. Then we should set the alias relationship.
     * @param a the HighSymbol a
     * @param b the HighSymbol b
     */
    public void setHighSymbolAlias(HighSymbol a, HighSymbol b) {
        Logging.debug("[Alias] Set symbol alias: " + a.getName() + " and " + b.getName());
        symbolAliasMap.union(a, b);
    }

    /**
     * Dump the current context to the log
     */
    public void dump() {
        for (var entry : typeBuilderMap.entrySet()) {
            Logging.info("HighSymbol: " + entry.getKey().getName());
            Logging.info("TypeBuilder: " + entry.getValue().toString());
        }
    }

    public Collection<HighSymbol> getHighSymbols() {
        return typeBuilderMap.keySet();
    }

    public boolean isEmpty() {
        return typeBuilderMap.isEmpty();
    }
}
