"""
如果你想让视图函数只对具有特定权限的用户开放，可以使用自定义的修饰器。示例 9-6
实现了两个修饰器，一个用来检查常规权限，一个专门用来检查管理员权限
"""

from functools import wraps
from flask import abort
from flask_login import current_user
from app.models import Permission

def permission_required(permission):
    def decorator(f): 
        @wraps(f) 
        def decorated_function(*args, **kwargs): 
            if not current_user.can(permission): 
                abort(403) 
            return f(*args, **kwargs) 
        return decorated_function 
    return decorator 
 
def admin_required(f): 
    return permission_required(Permission.ADMINISTER)(f)