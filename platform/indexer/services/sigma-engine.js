import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import chokidar from 'chokidar';
import yaml from 'js-yaml';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// In-memory rule cache
const rulesCache = new Map();
const RULES_DIR = path.join(__dirname, '..', 'rules');

export class SigmaEngine {
  constructor() {
    this.watcher = null;
    this.init();
  }

  init() {
    if (!fs.existsSync(RULES_DIR)) {
      fs.mkdirSync(RULES_DIR, { recursive: true });
    }

    // Watch the rules directory for changes
    this.watcher = chokidar.watch(RULES_DIR, { persistent: true, awaitWriteFinish: true });

    this.watcher
      .on('add', (filePath) => this.loadRule(filePath))
      .on('change', (filePath) => this.loadRule(filePath))
      .on('unlink', (filePath) => this.removeRule(filePath));

    console.log(`[Sigma Engine] Watching for rules in ${RULES_DIR}`);
  }

  loadRule(filePath) {
    if (!filePath.endsWith('.yml') && !filePath.endsWith('.yaml')) return;
    
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const rule = yaml.load(content);
      
      if (!rule || !rule.id || !rule.detection) {
        console.warn(`[Sigma Engine] Invalid rule format in ${filePath}`);
        return;
      }

      rule._filePath = filePath;
      rulesCache.set(rule.id, rule);
      console.log(`[Sigma Engine] Loaded rule: ${rule.title} (${rule.id})`);
    } catch (err) {
      console.error(`[Sigma Engine] Error parsing rule ${filePath}:`, err.message);
    }
  }

  removeRule(filePath) {
    for (const [id, rule] of rulesCache.entries()) {
      if (rule._filePath === filePath) {
        rulesCache.delete(id);
        console.log(`[Sigma Engine] Removed rule: ${rule.title} (${id})`);
        break;
      }
    }
  }

  getRules() {
    return Array.from(rulesCache.values());
  }

  getRule(id) {
    return rulesCache.get(id);
  }

  /**
   * Evaluates an event against all loaded Sigma rules.
   * @param {Object} event - The event object (should contain 'message' and 'fields').
   * @returns {Array} - List of matched rules.
   */
  evaluate(event) {
    const matches = [];
    for (const rule of rulesCache.values()) {
      if (this.evaluateRule(rule, event)) {
        matches.push(rule);
      }
    }
    return matches;
  }

  /**
   * Evaluates a single rule against an event.
   */
  evaluateRule(rule, event) {
    const { detection, logsource } = rule;
    if (!detection) return false;

    // Filter by logsource if provided (basic implementation)
    if (logsource) {
      const { product, category } = logsource;
      if (product && event.os && event.os.toLowerCase() !== product.toLowerCase()) {
        return false;
      }
      if (category && event.log_type && !event.log_type.includes(category)) {
        return false;
      }
    }

    const selections = {};
    let condition = detection.condition;

    // Evaluate each selection block
    for (const [key, value] of Object.entries(detection)) {
      if (key === 'condition') continue;
      selections[key] = this.evaluateSelection(value, event);
    }

    // Evaluate the condition
    if (!condition) {
       // If no condition but there is a 'selection', default to evaluating it
       if ('selection' in selections) return selections['selection'];
       return false;
    }

    // Very basic boolean evaluation (supports basic 'selection', 'selection and not filter', '1 of selection*')
    // A robust parser would use an AST, but we'll implement a functional Regex/Replace approach for the MVP.
    return this.evaluateConditionString(condition, selections);
  }

  evaluateConditionString(condition, selections) {
    // 1 of selection* => OR all selections starting with 'selection'
    if (condition.includes('1 of ')) {
      const target = condition.split('1 of ')[1].replace('*', '');
      return Object.keys(selections).some(k => k.startsWith(target) && selections[k]);
    }
    // all of selection* => AND all selections starting with 'selection'
    if (condition.includes('all of ')) {
      const target = condition.split('all of ')[1].replace('*', '');
      const matchedKeys = Object.keys(selections).filter(k => k.startsWith(target));
      if (matchedKeys.length === 0) return false;
      return matchedKeys.every(k => selections[k]);
    }

    // Direct replacement for evaluation (safe subset of boolean logic)
    let expr = condition;
    for (const key of Object.keys(selections)) {
      // Replace word boundary matching the key
      const regex = new RegExp(`\\b${key}\\b`, 'g');
      expr = expr.replace(regex, selections[key] ? 'true' : 'false');
    }

    // Evaluate the boolean expression string
    try {
      // Convert 'and', 'or', 'not' to JS operators
      const jsExpr = expr
        .replace(/\\bnot\\b/gi, '!')
        .replace(/\\band\\b/gi, '&&')
        .replace(/\\bor\\b/gi, '||');
      
      // eslint-disable-next-line no-new-func
      return new Function(`return !!(${jsExpr})`)();
    } catch (e) {
      console.error(`[Sigma Engine] Error evaluating condition: ${condition}`, e);
      return false;
    }
  }

  evaluateSelection(selectionNode, event) {
    if (Array.isArray(selectionNode)) {
      // If it's an array at the root of a selection, it means OR
      return selectionNode.some(item => this.evaluateSelection(item, event));
    }

    // Check all fields in the selection block (AND logic between fields)
    for (const [fieldExpr, expectedValue] of Object.entries(selectionNode)) {
      let field = fieldExpr;
      let modifiers = [];

      if (fieldExpr.includes('|')) {
        const parts = fieldExpr.split('|');
        field = parts[0];
        modifiers = parts.slice(1);
      }

      // Special field for raw message
      const eventValue = field === 'message' ? event.message : (event.fields && event.fields[field]);

      if (eventValue === undefined || eventValue === null) {
        return false; // Field not present
      }

      const match = this.evaluateValue(eventValue, expectedValue, modifiers);
      if (!match) return false;
    }

    return true; // All fields matched
  }

  evaluateValue(eventValue, expectedValue, modifiers) {
    const eventValStr = String(eventValue).toLowerCase();

    // If expectedValue is an array, it's an OR condition (any of them can match)
    if (Array.isArray(expectedValue)) {
      return expectedValue.some(exp => this.evaluateSingleValue(eventValStr, exp, modifiers));
    }
    
    return this.evaluateSingleValue(eventValStr, expectedValue, modifiers);
  }

  evaluateSingleValue(eventValStr, expectedValue, modifiers) {
    const expValStr = String(expectedValue).toLowerCase();
    
    if (modifiers.includes('contains')) {
      return eventValStr.includes(expValStr);
    }
    if (modifiers.includes('startswith')) {
      return eventValStr.startsWith(expValStr);
    }
    if (modifiers.includes('endswith')) {
      return eventValStr.endsWith(expValStr);
    }
    if (modifiers.includes('re')) {
      try {
        const regex = new RegExp(expectedValue, 'i');
        return regex.test(eventValStr);
      } catch (e) {
        return false;
      }
    }

    // Default: exact match or glob match (* and ?)
    if (expValStr.includes('*') || expValStr.includes('?')) {
      const globRegex = new RegExp('^' + expValStr.replace(/\\./g, '\\\\.').replace(/\\*/g, '.*').replace(/\\?/g, '.') + '$', 'i');
      return globRegex.test(eventValStr);
    }

    return eventValStr === expValStr;
  }
}

export const sigmaEngine = new SigmaEngine();
