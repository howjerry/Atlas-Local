// Empty Interface: should NOT trigger the rule
// Interfaces have members defined

// 有成員的 interface
interface UserConfig {
  timeout: number;
  retries: number;
}

// 有方法的 interface
interface Repository<T> {
  find(id: string): Promise<T>;
  save(entity: T): Promise<void>;
}

// 使用 type alias 取代空 interface
type EmptyObject = Record<string, never>;

// 有屬性的 Props
interface ButtonProps {
  label: string;
  onClick: () => void;
}
