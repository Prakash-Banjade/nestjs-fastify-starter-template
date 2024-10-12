import { SelectQueryBuilder } from "typeorm";

/**
 * Processes the column selection configuration and generates an array of selected columns.
 * @param {object} columns - The columns configuration object.
 * @param {string} alias - The alias used for the main entity.
 * @param {string[]} [path] - The current path for nested relations.
 * @returns {string[]} - An array of selected columns.
 */
function generateSelectColumns(columns: object, alias: string, path: string[] = []): string[] {
    let selections: string[] = [];

    for (const [key, value] of Object.entries(columns)) {
        const columnPath = [...path, key].join('.');

        if (typeof value === 'boolean' && value) {
            selections.push(`${alias}.${columnPath}`);
        } else if (typeof value === 'object' && value !== null) {
            if (path.length === 0) {
                const nestedSelections = generateSelectColumns(value, key, []);
                selections = selections.concat(nestedSelections);
            } else {
                const nestedSelections = generateSelectColumns(value, alias, [...path, key]);
                selections = selections.concat(nestedSelections);
            }
        }
    }

    return selections;
}

/**
 * Adds the selected columns to the query builder.
 * @param {SelectQueryBuilder<T>} queryBuilder - The TypeORM query builder instance.
 * @param {object} columns - The columns configuration object.
 * @param {string} alias - The alias used for the main entity.
 */
export function applySelectColumns<T>(queryBuilder: SelectQueryBuilder<T>, columns: object, alias: string): void {
    const selections = generateSelectColumns(columns, alias);
    queryBuilder.select(selections);
}