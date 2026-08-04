// ============================================================
// TRACKATOR Tier 1 - State Inventory
// Computes storage layouts, slot assignments, and type sizes
// ============================================================

import {
  SolidityContract,
  StateVariable,
  StructDef,
  StorageSlotInfo,
  MappingSlotInfo
} from '../types';

export interface StateInventory {
  contract: string;
  totalSlots: number;
  variables: InventoryItem[];
  mappings: MappingInventory[];
  structs: StructLayout[];
  potentialPackingIssues: PackingIssue[];
}

export interface InventoryItem {
  variable: StateVariable;
  computedSlot: number;
  offset: number;
  byteSize: number;
  typeInfo: TypeInfo;
  packedWith: string[];  // Variables sharing this slot
}

export interface TypeInfo {
  category: 'value' | 'reference' | 'mapping' | 'array' | 'struct' | 'enum';
  encoding: 'tight' | 'abi' | 'none';
  staticSize: number;    // Bytes if fixed size, -1 if dynamic
  keyType?: string;      // For mappings
  valueType?: string;    // For mappings/arrays
}

export interface MappingInventory {
  variable: string;
  slot: number;
  keyType: string;
  valueType: string;
  valueSlotBase: string; // keccak256(abi.encode(slot, key))
}

export interface StructLayout {
  name: string;
  members: MemberLayout[];
  totalSize: number;
}

export interface MemberLayout {
  name: string;
  type: string;
  slot: number;
  offset: number;
  size: number;
}

export interface PackingIssue {
  slot: number;
  variables: string[];
  wastedBytes: number;
  suggestion: string;
}

/**
 * Generate complete state inventory for a contract
 */
export function generateStateInventory(contract: SolidityContract): StateInventory {
  const variables: InventoryItem[] = [];
  const mappings: MappingInventory[] = [];
  const packingIssues: PackingIssue[] = [];
  
  let currentSlot = 0;
  let currentOffset = 0;
  let slotVariables: string[] = [];
  let slotUsedBytes = 0;
  
  for (const stateVar of contract.stateVariables) {
    // Skip constants and immutables (not in storage)
    if (stateVar.visibility === 'constant' || stateVar.visibility === 'immutable') {
      continue;
    }
    
    const typeInfo = analyzeType(stateVar.type, contract.structs);
    const item: InventoryItem = {
      variable: stateVar,
      computedSlot: currentSlot,
      offset: currentOffset,
      byteSize: typeInfo.staticSize > 0 ? typeInfo.staticSize : 32,
      typeInfo,
      packedWith: []
    };
    
    if (typeInfo.category === 'mapping') {
      // Mappings always get their own slot
      mappings.push({
        variable: stateVar.name,
        slot: currentSlot,
        keyType: typeInfo.keyType || 'unknown',
        valueType: typeInfo.valueType || 'unknown',
        valueSlotBase: `keccak256(abi.encode(${currentSlot}, key))`
      });
      
      currentSlot++;
      currentOffset = 0;
      slotVariables = [stateVar.name];
      slotUsedBytes = 0;
    } else if (typeInfo.staticSize === -1) {
      // Dynamic arrays - slot holds length, data at keccak256(slot)
      currentSlot++;
      currentOffset = 0;
      slotVariables = [stateVar.name];
      slotUsedBytes = 0;
    } else if (typeInfo.staticSize <= (32 - currentOffset)) {
      // Can pack into current slot
      item.computedSlot = currentSlot;
      item.offset = currentOffset;
      item.packedWith = [...slotVariables];
      
      slotVariables.push(stateVar.name);
      slotUsedBytes += typeInfo.staticSize;
      currentOffset += typeInfo.staticSize;
      
      if (currentOffset >= 32) {
        currentSlot++;
        currentOffset = 0;
        slotVariables = [];
        slotUsedBytes = 0;
      }
    } else {
      // Needs new slot
      if (slotUsedBytes > 0 && slotUsedBytes < 32) {
        packingIssues.push({
          slot: currentSlot,
          variables: [...slotVariables],
          wastedBytes: 32 - slotUsedBytes,
          suggestion: `Consider reordering variables to fill slot ${currentSlot}`
        });
      }
      
      currentSlot++;
      currentOffset = 0;
      item.computedSlot = currentSlot;
      item.offset = 0;
      slotVariables = [stateVar.name];
      slotUsedBytes = typeInfo.staticSize;
      currentOffset = typeInfo.staticSize;
    }
    
    variables.push(item);
  }
  
  // Check final slot
  if (slotUsedBytes > 0 && slotUsedBytes < 32) {
    packingIssues.push({
      slot: currentSlot,
      variables: [...slotVariables],
      wastedBytes: 32 - slotUsedBytes,
      suggestion: `Consider reordering variables to fill slot ${currentSlot}`
    });
  }
  
  // Compute struct layouts
  const structLayouts = contract.structs.map(s => computeStructLayout(s));
  
  return {
    contract: contract.name,
    totalSlots: currentSlot + (currentOffset > 0 ? 1 : 0),
    variables,
    mappings,
    structs: structLayouts,
    potentialPackingIssues: packingIssues
  };
}

/**
 * Analyze a Solidity type and return its properties
 */
function analyzeType(
  typeStr: string,
  structs: StructDef[]
): TypeInfo {
  const trimmed = typeStr.trim();
  
  // Mapping types
  const mappingMatch = trimmed.match(/mapping\s*\(\s*(\w[\w\[\]]*)\s*=>\s*(\w[\w\[\]]*)\s*\)/);
  if (mappingMatch) {
    return {
      category: 'mapping',
      encoding: 'none',
      staticSize: 32,
      keyType: mappingMatch[1],
      valueType: mappingMatch[2]
    };
  }
  
  // Array types
  const arrayMatch = trimmed.match(/^(\w[\w\[\]]*)(\[\d*\])$/);
  if (arrayMatch) {
    const baseType = arrayMatch[1];
    const arrayPart = arrayMatch[2];
    
    if (arrayPart === '[]') {
      // Dynamic array
      return {
        category: 'array',
        encoding: 'abi',
        staticSize: -1,
        valueType: baseType
      };
    } else {
      // Fixed-size array
      const sizeMatch = arrayPart.match(/\[(\d+)\]/);
      const count = parseInt(sizeMatch?.[1] || '0');
      const elementSize = getPrimitiveSize(baseType);
      return {
        category: 'array',
        encoding: 'tight',
        staticSize: elementSize * count,
        valueType: baseType
      };
    }
  }
  
  // Check if it's a custom struct
  const structDef = structs.find(s => s.name === trimmed);
  if (structDef) {
    const structSize = computeStructSize(structDef, structs);
    return {
      category: 'struct',
      encoding: 'abi',
      staticSize: structSize
    };
  }
  
  // Primitive types
  const primitiveSize = getPrimitiveSize(trimmed);
  return {
    category: 'value',
    encoding: 'tight',
    staticSize: primitiveSize
  };
}

/**
 * Get size in bytes for primitive Solidity types
 */
function getPrimitiveSize(typeStr: string): number {
  const sizes: { [key: string]: number } = {
    'bool': 1,
    'address': 20,
    'uint8': 1, 'uint16': 2, 'uint24': 3, 'uint32': 4, 'uint40': 5,
    'uint48': 6, 'uint56': 7, 'uint64': 8, 'uint72': 9, 'uint80': 10,
    'uint88': 11, 'uint96': 12, 'uint104': 13, 'uint112': 14, 'uint120': 15,
    'uint128': 16, 'uint136': 17, 'uint144': 18, 'uint152': 19, 'uint160': 20,
    'uint168': 21, 'uint176': 22, 'uint184': 23, 'uint192': 24, 'uint200': 25,
    'uint208': 26, 'uint216': 27, 'uint224': 28, 'uint232': 29, 'uint240': 30,
    'uint248': 31, 'uint256': 32,
    'int8': 1, 'int16': 2, 'int24': 3, 'int32': 4, 'int40': 5,
    'int48': 6, 'int56': 7, 'int64': 8, 'int72': 9, 'int80': 10,
    'int88': 11, 'int96': 12, 'int104': 13, 'int112': 14, 'int120': 15,
    'int128': 16, 'int136': 17, 'int144': 18, 'int152': 19, 'int160': 20,
    'int168': 21, 'int176': 22, 'int184': 23, 'int192': 24, 'int200': 25,
    'int208': 26, 'int216': 27, 'int224': 28, 'int232': 29, 'int240': 30,
    'int248': 31, 'int256': 32,
    'bytes1': 1, 'bytes2': 2, 'bytes3': 3, 'bytes4': 4, 'bytes5': 5,
    'bytes6': 6, 'bytes7': 7, 'bytes8': 8, 'bytes9': 9, 'bytes10': 10,
    'bytes11': 11, 'bytes12': 12, 'bytes13': 13, 'bytes14': 14, 'bytes15': 15,
    'bytes16': 16, 'bytes17': 17, 'bytes18': 18, 'bytes19': 19, 'bytes20': 20,
    'bytes21': 21, 'bytes22': 22, 'bytes23': 23, 'bytes24': 24, 'bytes25': 25,
    'bytes26': 26, 'bytes27': 27, 'bytes28': 28, 'bytes29': 29, 'bytes30': 30,
    'bytes31': 31, 'bytes32': 32,
    'string': -1,  // Dynamic
    'bytes': -1     // Dynamic
  };
  
  return sizes[typeStr.toLowerCase()] || 32; // Default to 32 bytes
}

/**
 * Compute storage layout for a struct definition
 */
function computeStructLayout(structDef: StructDef): StructLayout {
  const members: MemberLayout[] = [];
  let currentSlot = 0;
  let currentOffset = 0;
  
  for (const member of structDef.members) {
    const size = getPrimitiveSize(member.type);
    
    members.push({
      name: member.name,
      type: member.type,
      slot: currentSlot,
      offset: currentOffset,
      size
    });
    
    currentOffset += size;
    if (currentOffset >= 32) {
      currentSlot++;
      currentOffset = 0;
    }
  }
  
  return {
    name: structDef.name,
    members,
    totalSize: currentSlot * 32 + currentOffset
  };
}

/**
 * Compute total size of a struct in bytes
 */
function computeStructSize(structDef: StructDef, allStructs: StructDef[]): number {
  let size = 0;
  
  for (const member of structDef.members) {
    // Check if member is another struct
    const nestedStruct = allStructs.find(s => s.name === member.type);
    if (nestedStruct) {
      size += computeStructSize(nestedStruct, allStructs);
    } else {
      const memberSize = getPrimitiveSize(member.type);
      if (memberSize === -1) {
        return -1; // Contains dynamic type
      }
      size += memberSize;
    }
  }
  
  return size;
}

/**
 * Generate inventory for multiple contracts
 */
export function generateAllInventories(contracts: SolidityContract[]): Map<string, StateInventory> {
  const inventories = new Map<string, StateInventory>();
  
  for (const contract of contracts) {
    inventories.set(contract.name, generateStateInventory(contract));
  }
  
  return inventories;
}

/**
 * Find variable by slot number
 */
export function findVariableBySlot(
  inventory: StateInventory,
  slot: number,
  offset?: number
): InventoryItem | null {
  for (const item of inventory.variables) {
    if (item.computedSlot === slot) {
      if (offset === undefined || item.offset === offset) {
        return item;
      }
    }
  }
  return null;
}

/**
 * Decode raw storage value based on type information
 */
export function decodeStorageValue(
  hexValue: string,
  typeInfo: TypeInfo,
  offset?: number
): any {
  // Remove 0x prefix if present
  const cleanHex = hexValue.startsWith('0x') ? hexValue.slice(2) : hexValue;
  
  // Pad to 64 characters (32 bytes)
  const padded = cleanHex.padStart(64, '0');
  
  switch (typeInfo.category) {
    case 'value':
      return decodePrimitive(padded, typeInfo.staticSize, offset || 0);
    
    case 'mapping':
      return `<Mapping at slot ${padded}>`;
    
    case 'array':
      if (typeInfo.staticSize === -1) {
        return `Dynamic array, length: ${parseInt(padded, 16)}`;
      }
      return `Fixed array[${typeInfo.staticSize / 32}]`;
    
    default:
      return `0x${padded}`;
  }
}

function decodePrimitive(hex: string, size: number, offset: number): any {
  // Extract relevant bytes
  const startByte = 64 - (offset + size) * 2;
  const endByte = 64 - offset * 2;
  const valueHex = hex.substring(startByte, endByte);
  
  const bigint = BigInt('0x' + valueHex);
  
  // Try to interpret as signed or unsigned based on typical patterns
  if (size <= 32) {
    // Could be uint or int
    const maxUnsigned = BigInt(2) ** BigInt(size * 8);
    const halfPoint = BigInt(2) ** BigInt(size * 8 - 1);
    
    if (bigint >= halfPoint) {
      // Interpret as negative (two's complement)
      return Number(bigint - maxUnsigned);
    }
    return Number(bigint);
  }
  
  return bigint.toString();
}

// Export additional utility types
export { MappingSlotInfo };
