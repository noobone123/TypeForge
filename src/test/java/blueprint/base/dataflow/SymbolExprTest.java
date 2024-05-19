package blueprint.base.dataflow;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighSymbol;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SymbolExprTest {
    @Mock
    private HighSymbol mockHighSymbol1;
    @Mock
    private HighSymbol mockHighSymbol2;
    @Mock
    private HighSymbol mockHighSymbol3;

    @BeforeEach
    public void setUp() {
        when(mockHighSymbol1.getName()).thenReturn("mock_1");
        when(mockHighSymbol2.getName()).thenReturn("mock_2");
        when(mockHighSymbol3.getName()).thenReturn("mock_3");
    }

    @Test
    public void test() {
        var expr1 = new SymbolExpr.Builder()
                        .rootSymbol(mockHighSymbol1)
                        .build();

        var expr2 = new SymbolExpr.Builder()
                        .rootSymbol(mockHighSymbol2)
                        .build();

        var expr3 = new SymbolExpr.Builder()
                        .rootSymbol(mockHighSymbol3)
                        .build();


        assertEquals(expr1.getRepresentation(), "mock_1");
        assertEquals(expr2.getRepresentation(), "mock_2");
        assertEquals(expr3.getRepresentation(), "mock_3");

        var expr4 = new SymbolExpr.Builder().constant(0x8).build();
        var expr5 = new SymbolExpr.Builder().constant(0x10).build();
        var expr6 = new SymbolExpr.Builder().constant(0x18).build();

        assertEquals(expr4.getRepresentation(), "0x8");
        assertEquals(expr5.getRepresentation(), "0x10");
        assertEquals(expr6.getRepresentation(), "0x18");

        var expr7 = expr1.add(expr4);
        var expr8 = expr2.add(expr5);
        var expr9 = expr3.add(expr6);
        assertEquals(expr7.getRepresentation(), "mock_1 + 0x8");
        assertEquals(expr8.getRepresentation(), "mock_2 + 0x10");
        assertEquals(expr9.getRepresentation(), "mock_3 + 0x18");
    }
}