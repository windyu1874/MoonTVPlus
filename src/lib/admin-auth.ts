import { getAuthInfoFromCookie } from '@/lib/auth';

const ADMIN_ROLES = ['owner', 'admin'];

export interface AdminAccess {
  ok: boolean;
  /** 站长本人（用户名等于环境变量 USERNAME），拥有全部权限 */
  isOwner: boolean;
  /** 当前用户是否为被封禁状态 */
  banned: boolean;
}

/**
 * 统一的管理员判定：站长（环境变量 USERNAME）恒为 owner，
 * 数据库中的 owner/admin 角色均可进入后台。
 *
 * 早先各接口自带一份判断，且普遍写成「role 必须是 admin」，
 * 而 getUserInfoV2 会把站长记录的角色改写成 owner，
 * 导致站长在所有后台接口都被拒成 401。集中到这里避免再分叉。
 */
export async function resolveAdminAccess(
  request: Request
): Promise<AdminAccess> {
  const authInfo = getAuthInfoFromCookie(request as Parameters<typeof getAuthInfoFromCookie>[0]);
  const username = authInfo?.username;

  if (!username) {
    return { ok: false, isOwner: false, banned: false };
  }

  const isOwner = !process.env.USERNAME || username === process.env.USERNAME;
  if (isOwner) {
    return { ok: true, isOwner: true, banned: false };
  }

  // 角色存放在数据库中；同时优先采信登录 cookie 里已签名的角色，
  // 避免数据库里 owner 记录被误判成普通用户。
  let dbRole: string | undefined;
  let banned = false;

  try {
    const { db } = await import('@/lib/db');
    const userInfo = await db.getUserInfoV2(username);
    if (userInfo) {
      dbRole = userInfo.role;
      banned = Boolean(userInfo.banned);
    }
  } catch (error) {
    console.error('resolveAdminAccess 读取用户信息失败:', error);
  }

  // 旧版 cookie 里没有 role 字段，这里回落到管理员角色即可，
  // 中间的 verifySignature 已经验过 cookie 未被篡改。
  const role = String(dbRole || authInfo?.role || 'admin');
  const ok = !banned && ADMIN_ROLES.includes(role);

  return { ok, isOwner: false, banned };
}