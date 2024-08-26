package typeclay.base.passes;

import typeclay.base.dataflow.AccessPoints;
import typeclay.base.dataflow.skeleton.Skeleton;
import typeclay.utils.DataTypeHelper;
import typeclay.utils.Global;
import ghidra.program.model.data.DataType;

import java.util.Map;
import java.util.TreeMap;

public class Window {
    private final Map<Integer, Object> windowElements;
    private int windowSize;
    private final Map<Integer, Integer> ptrLevel;

    public Window() {
        this.windowElements = new TreeMap<>();
        this.windowSize = 0;
        this.ptrLevel = new TreeMap<>();
    }

    public void addElement(int offset, Object element) {
        windowElements.put(offset, element);
    }

    public void addPtrLevel(int offset, int level) {
        ptrLevel.put(offset, level);
    }

    /**
     * Get the Aligned Window's Size
     * @return aligned window's size
     */
    public int getAlignedWindowSize() {
        if (windowSize != 0) {
            return windowSize;
        }

        long totalSize = 0;
        long maxAlignSize = 1;
        for (var element: windowElements.values()) {
            long fieldSize;
            long fieldAlignSize = 1;
            if (element instanceof Skeleton) {
                fieldSize = Global.currentProgram.getDefaultPointerSize();
                fieldAlignSize = fieldSize;
            }
            else {
                fieldSize = ((AccessPoints.APSet) element).mostAccessedDT.getLength();
                fieldAlignSize = ((AccessPoints.APSet) element).mostAccessedDT.getAlignment();
            }

            if (totalSize % fieldAlignSize != 0) {
                totalSize += fieldAlignSize - (totalSize % fieldAlignSize);
            }

            totalSize += fieldSize;
            if (fieldAlignSize > maxAlignSize) {
                maxAlignSize = fieldAlignSize;
            }
        }

        if (totalSize % maxAlignSize != 0) {
            totalSize += maxAlignSize - (totalSize % maxAlignSize);
        }

        windowSize = (int) totalSize;
        return windowSize;
    }

    public DataType getWindowDT() {
        if (windowElements.size() == 1) {
            var element = windowElements.get(0);
            if (element instanceof AccessPoints.APSet apSet) {
                return apSet.mostAccessedDT;
            } else {
                return DataTypeHelper.getDataTypeByName("void");
            }
        }
        else if (windowElements.size() > 1) {
            return DataTypeHelper.createAnonStructureFromWindow(this);
        } else {
            return null;
        }
    }

    public Map<Integer, Object> getWindowElements() {
        return windowElements;
    }

    public Map<Integer, Integer> getPtrLevel() {
        return ptrLevel;
    }

    public boolean isHomogeneous() {
        if (windowElements.size() == 1) {
            return false;
        }

        var firstElement = windowElements.get(0);
        if (firstElement instanceof Skeleton skt) {
            for (var element: windowElements.values()) {
                if (!(element instanceof Skeleton) || !element.equals(skt)) {
                    return false;
                }
            }
            return true;
        } else if (firstElement instanceof AccessPoints.APSet apSet) {
            for (var element: windowElements.values()) {
                if (!(element instanceof AccessPoints.APSet)) {
                    return false;
                }
                var otherAPSet = (AccessPoints.APSet) element;
                if (apSet.DTSize != otherAPSet.DTSize) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (var entry: windowElements.entrySet()) {
            int offset = entry.getKey();
            Object element = entry.getValue();
            sb.append(String.format("0x%x", offset)).append(": ");
            if (element instanceof Skeleton skt) {
                sb.append(skt.toString());
            } else if (element instanceof AccessPoints.APSet apSet) {
                sb.append(apSet.mostAccessedDT.getName());
            }
            sb.append("\n");
        }
        sb.append("Size: ").append(getAlignedWindowSize());
        return sb.toString();
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Window otherWindow)) {
            return false;
        }

        if (windowElements.size() != otherWindow.windowElements.size()) {
            return false;
        }
        if (!windowElements.keySet().equals(otherWindow.windowElements.keySet())) {
            return false;
        }
        for (var entry: windowElements.entrySet()) {
            int offset = entry.getKey();
            Object e1 = entry.getValue();
            Object e2 = otherWindow.windowElements.get(offset);

            if (e1 instanceof Skeleton && e2 instanceof Skeleton) {
                if (!e1.equals(e2)) {
                    return false;
                }
            } else if (e1 instanceof AccessPoints.APSet s1 && e2 instanceof AccessPoints.APSet s2) {
                if (s1.DTSize != s2.DTSize) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return true;
    }

}
