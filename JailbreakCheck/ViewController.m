//
//  ViewController.m
//  JailbreakCheck
//
//  Created by user on 2018/8/16.
//  Copyright © 2018年 imobpay. All rights reserved.
//  参考博客：https://blog.csdn.net/yiyaaixuexi/article/details/20286929

#import "ViewController.h"
#import <sys/stat.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSLog(@"%d",[self isJailbroken]);
    [self checkAppList];
    checkCydia();
    checkInject();
    checkDylibs();
    printEnv();
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}
/*
 1、写成BOOL开关方法，给攻击者直接锁定目标hook绕过的机会
 2、攻击者可能会改变这些工具的安装路径，躲过判断
 /Applications/Cydia.app
 /Library/MobileSubstrate/MobileSubstrate.dylib
 /bin/bash
 /usr/sbin/sshd
 /etc/apt
 */
-(BOOL)isJailbroken{
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]){
        return YES;
    }
    // ...
    return NO;
}

/*
 尝试读取下应用列表，看看有无权限获取
 缺陷：攻击者可能会hook NSFileManager 的方法
 */
-(void)checkAppList{
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/User/Applications/"]){
        NSLog(@"Device is jailbroken");
        NSArray *applist = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/User/Applications/"
                                                                               error:nil];
        NSLog(@"applist = %@",applist);
    }else{
       NSLog(@"Device is not jailbroken");
    }

}

/*
 使用stat系列函数检测Cydia等工具
 缺陷：攻击者可能会利用 Fishhook原理 hook了stat。
 */
void checkCydia(void)
{
    struct stat stat_info;
    if (0 == stat("/Applications/Cydia.app", &stat_info)) {
        NSLog(@"Device is jailbroken");
    }else{
        NSLog(@"Device is not jailbroken1");
    }
}

/*
 stat是否出自系统库，是否被攻击者换掉
 如果结果不是 /usr/lib/system/libsystem_kernel.dylib 的话，那就100%被攻击了。
 缺陷：攻击者可能替换libsystem_kernel.dylib 绕过检测。
 */
void checkInject(void)
{
    int ret ;
    Dl_info dylib_info;
    int    (*func_stat)(const char *, struct stat *) = stat;
    if ((ret = dladdr(func_stat, &dylib_info))) {
        NSLog(@"lib :%s", dylib_info.dli_fname);
    }
}
/*
 检索一下应用程序是否被链接了异常动态库
 如果包含越狱机的输出结果会包含字符串： Library/MobileSubstrate/MobileSubstrate.dylib ，那可能被攻击了。
 缺陷：攻击者可能会给MobileSubstrate改名， 绕过检测。但是原理都是通过DYLD_INSERT_LIBRARIES注入动态库
 */
void checkDylibs(void)
{
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0 ; i < count; ++i) {
        NSString *name = [[NSString alloc]initWithUTF8String:_dyld_get_image_name(i)];
        NSLog(@"--%@", name);
    }
}
/*
 检测当前程序运行的环境变量
 未越狱设备返回结果是null，越狱设备就各有各的精彩
 */
void printEnv(void)
{
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    NSLog(@"%s", env);
}

@end
