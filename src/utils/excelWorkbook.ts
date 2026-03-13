import * as XLSX from 'xlsx';

const EXCEL_WORKBOOK_AUTHOR = '11ArkaN';

export function createWorkbookWithMetadata(): XLSX.WorkBook {
  const workbook = XLSX.utils.book_new();
  workbook.Props = {
    Author: EXCEL_WORKBOOK_AUTHOR,
    LastAuthor: EXCEL_WORKBOOK_AUTHOR
  };
  return workbook;
}
