package burp;

import javax.swing.table.AbstractTableModel;

public class HttpLogTableModel extends AbstractTableModel {
    public int getRowCount() {
        return BurpExtender.log.size();
    }

    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int columnIndex) {

        switch (columnIndex)
        {
            case 0:
                return "URL";
            case 1:
                return "Method";
            case 2:
                return "Status";
            case 3:
                return "Vul name";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }


    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = BurpExtender.log.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.method;
            case 2:
                return logEntry.status;
            case 3:
                return logEntry.vulName;
            default:
                return "";
        }
    }
}