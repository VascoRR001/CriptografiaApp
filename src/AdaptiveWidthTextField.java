import javax.swing.JTextField;
import java.awt.Dimension;
import java.awt.FontMetrics;

public class AdaptiveWidthTextField extends JTextField {

    public AdaptiveWidthTextField(String text) {
        super(text);
    }

    @Override
    public Dimension getPreferredSize() {
        FontMetrics metrics = getFontMetrics(getFont());
        int width = metrics.stringWidth(getText()) + getInsets().left + getInsets().right;
        int height = super.getPreferredSize().height;
        return new Dimension(width, height);
    }
}
