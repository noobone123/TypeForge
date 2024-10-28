package typeforge.base.dataflow.types;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Pointer;

import java.util.HashMap;
import java.util.Map;

public class CompositeTypeDescriptor implements TypeDescriptor {
    private String typeName = null;
    private Map<Integer, TypeDescriptor> fieldMap = new HashMap<>();
    private Map<Integer, Integer> fieldPtrLevelMap = new HashMap<>();

    public CompositeTypeDescriptor(Composite compositeDT) {
        this.typeName = compositeDT.getName();
        for (var field: compositeDT.getComponents()) {
            var fieldOffset = field.getOffset();
            var fieldType = field.getDataType();

            if (fieldType instanceof Pointer ptr) {
                var ptrLevel = 1;
                var ptreeDT = ptr.getDataType();
                while (ptreeDT instanceof Pointer) {
                    ptreeDT = ((Pointer) ptreeDT).getDataType();
                    ptrLevel++;
                }
                fieldPtrLevelMap.put(fieldOffset, ptrLevel);
                if (ptreeDT instanceof Composite com) {
                    if (ptreeDT == compositeDT) {
                        // Recursive pointer
                        fieldMap.put(fieldOffset, this);
                    } else {
                        fieldMap.put(fieldOffset, TypeDescriptorManager.createCompositeTypeDescriptor(com));
                    }
                } else {
                    fieldMap.put(fieldOffset, TypeDescriptorManager.createPrimitiveTypeDescriptor(ptreeDT));
                }
            }
            else if (fieldType instanceof Composite com) {
                fieldPtrLevelMap.put(fieldOffset, 0);
                if (com == compositeDT) {
                    // Recursive composite
                    fieldMap.put(fieldOffset, this);
                } else {
                    fieldMap.put(fieldOffset, TypeDescriptorManager.createCompositeTypeDescriptor(com));
                }
            }
            else if (fieldType instanceof Array array) {
                fieldPtrLevelMap.put(fieldOffset, 0);
                fieldMap.put(fieldOffset, TypeDescriptorManager.createArrayTypeDescriptor(array));
            }
            else {
                fieldPtrLevelMap.put(fieldOffset, 0);
                fieldMap.put(fieldOffset, TypeDescriptorManager.createPrimitiveTypeDescriptor(fieldType));
            }
        }
    }

    public CompositeTypeDescriptor(Map<Long, TypeDescriptor> fieldMap) {
        // TODO ...
    }

    @Override
    public String getName() {
        return typeName;
    }

    @Override
    public String toString() {
        return "CompositeType{" +
                "typeName='" + typeName + '\'' +
                '}';
    }

    @Override
    public int hashCode() {
        return System.identityHashCode(this);
    }

    @Override
    public boolean equals(Object obj) {
        return this == obj;
    }
}
